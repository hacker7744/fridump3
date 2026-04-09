import os
import logging

# Reading bytes from session and saving it to a file

def _to_int_safe(x):
    try:
        if isinstance(x, int):
            return x
        if isinstance(x, str):
            s = x.strip()
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            return int(s)
        return int(x)
    except Exception:
        # best-effort fallback
        return int(float(str(x).strip()))


def dump_to_file(agent, base, size, error, directory):
    """
    Read memory via agent and save to file.
    agent may be the script.exports_sync proxy; agent.read_memory/_readMemory/_readMemory will map to JS.
    """
    try:
        filename = "{:x}_dump.data".format(int(base))
        # call agent.read_memory (ScriptExportsSync will map snake_case->camelCase),
        # but we try several names to be robust.
        dump = None
        for fn_name in ("read_memory", "readmemory", "readMemory"):
            try:
                func = getattr(agent, fn_name)
            except Exception:
                func = None
            if func:
                try:
                    dump = func(base, size)
                    break
                except Exception as e:
                    logging.debug("Attempt to read with %s failed: %s", fn_name, e)
                    dump = None

        if dump is None:
            # nothing read
            raise IOError("Failed to read memory at 0x{:x} size {}".format(int(base), int(size)))

        # Frida RPC may return bytes directly, or a tuple (value, data) depending on serialization;
        # normalize to raw bytes.
        raw_bytes = None
        if isinstance(dump, tuple) or isinstance(dump, list):
            # Most often the data comes back as the data parameter (second element) or the first
            if len(dump) == 2 and isinstance(dump[1], (bytes, bytearray, memoryview)):
                raw_bytes = bytes(dump[1])
            elif isinstance(dump[0], (bytes, bytearray, memoryview)):
                raw_bytes = bytes(dump[0])
            else:
                # try to coerce the second element
                raw_bytes = bytes(dump[1]) if len(dump) > 1 else bytes(dump[0])
        elif isinstance(dump, (bytes, bytearray, memoryview)):
            raw_bytes = bytes(dump)
        else:
            # attempt to convert other types to bytes (e.g., array buffer repr)
            try:
                raw_bytes = bytes(dump)
            except Exception:
                # last resort: convert str to bytes
                raw_bytes = str(dump).encode('latin-1', errors='ignore')

        path = os.path.join(directory, filename)
        with open(path, 'wb') as f:
            f.write(raw_bytes)
        return error
    except Exception as e:
        logging.debug(str(e))
        print("Oops, memory access violation at base {} size {}!".format(base, size))
        return error


# Read bytes that are bigger than the max_size value, split them into chunks and save them to a file
def splitter(agent, base, size, max_size, error, directory):
    """
    base may be int or hex string. This splits [base, base+size) into max_size chunks.
    """
    try:
        cur_base = _to_int_safe(base)
    except Exception:
        cur_base = int(base)

    total = int(size)
    if total <= 0:
        return error

    # How many full chunks, and remainder
    times = total // max_size
    remainder = total % max_size

    # if exactly divisible, we'll have 'times' full chunks and no remainder
    # iterate through full chunks
    for i in range(times):
        logging.debug("Saving chunk %d: 0x%X - 0x%X", i, cur_base, cur_base + max_size)
        dump_to_file(agent, cur_base, max_size, error, directory)
        cur_base += max_size

    if remainder != 0:
        logging.debug("Saving final remainder chunk: 0x%X - 0x%X", cur_base, cur_base + remainder)
        dump_to_file(agent, cur_base, remainder, error, directory)

    return error
