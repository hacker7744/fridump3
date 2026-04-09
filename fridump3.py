import textwrap
import frida
import os
import sys
import frida.core
import dumper
import utils
import argparse
import logging

logo = """
        ______    _     _
        |  ___|  (_)   | |
        | |_ _ __ _  __| |_   _ _ __ ___  _ __
        |  _| '__| |/ _` | | | | '_ ` _ \\| '_ \\
        | | | |  | | (_| | |_| | | | | | | |_) |
        \\_| |_|  |_|\__,_|\\__,_|_| |_| |_| .__/
                                         | |
                                         |_|
        """

# Main Menu
def MENU():
    parser = argparse.ArgumentParser(
        prog='fridump',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(""))

    parser.add_argument(
        'process', help='the process that you will be injecting to')
    parser.add_argument('-o', '--out', type=str, help='provide full output directory path. (def: \'dump\')',
                        metavar="dir")
    parser.add_argument('-u', '--usb', action='store_true',
                        help='device connected over usb')
    parser.add_argument('-H', '--host', type=str,
                        help='device connected over IP')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('-r', '--read-only', action='store_true',
                        help="dump read-only parts of memory. More data, more errors")
    parser.add_argument('-s', '--strings', action='store_true',
                        help='run strings on all dump files. Saved in output dir.')
    parser.add_argument('--max-size', type=int, help='maximum size of dump file in bytes (def: 20971520)',
                        metavar="bytes")
    args = parser.parse_args()
    return args


print(logo)

arguments = MENU()

# Define Configurations
APP_NAME = utils.normalize_app_name(appName=arguments.process)
DIRECTORY = ""
USB = arguments.usb
NETWORK = False
DEBUG_LEVEL = logging.INFO
STRINGS = arguments.strings
MAX_SIZE = 20971520
PERMS = 'rw-'

if arguments.host is not None:
    NETWORK = True
    IP = arguments.host

if arguments.read_only:
    PERMS = 'r--'

if arguments.verbose:
    DEBUG_LEVEL = logging.DEBUG
logging.basicConfig(format='%(levelname)s:%(message)s', level=DEBUG_LEVEL)


# Start a new Session
session = None
try:
    if USB:
        session = frida.get_usb_device().attach(APP_NAME)
    elif NETWORK:
        session = frida.get_device_manager().add_remote_device(IP).attach(APP_NAME)
    else:
        session = frida.attach(APP_NAME)
except Exception as e:
    print(str(e))
    sys.exit()


# Selecting Output directory
if arguments.out is not None:
    DIRECTORY = arguments.out
    if os.path.isdir(DIRECTORY):
        print("Output directory is set to: " + DIRECTORY)
    else:
        print("The selected output directory does not exist!")
        sys.exit(1)

else:
    print("Current Directory: " + str(os.getcwd()))
    DIRECTORY = os.path.join(os.getcwd(), "dump")
    print("Output directory is set to: " + DIRECTORY)
    if not os.path.exists(DIRECTORY):
        print("Creating directory...")
        os.makedirs(DIRECTORY)

mem_access_viol = ""

print("Starting Memory dump...")


def on_message(message, data):
    # Keep message logging simple and useful
    logging.debug("[on_message] message: %s, data: %s", message, "<binary>" if data else None)


# Robust JS agent: export multiple RPC names and call enumerateMemoryRanges* (broad compatibility)
# Robust JS agent: export multiple RPC names and call enumerateMemoryRanges* (broad compatibility)
js_agent = r"""'use strict';

function _enumRanges(prot) {
  var lastErr = null;
  try {
    if (typeof Process.enumerateMemoryRanges === 'function') {
      return Process.enumerateMemoryRanges({ protection: prot });
    }
  } catch (e) { lastErr = e; }
  try {
    if (typeof Process.enumerateMemoryRangesSync === 'function') {
      return Process.enumerateMemoryRangesSync({ protection: prot });
    }
  } catch (e) { lastErr = e; }
  try {
    if (typeof Process.enumerateRanges === 'function') {
      return Process.enumerateRanges(prot);
    }
  } catch (e) { lastErr = e; }
  try {
    if (typeof Process.enumerateRangesSync === 'function') {
      return Process.enumerateRangesSync(prot);
    }
  } catch (e) { lastErr = e; }

  throw new Error("No compatible Process.enumerate*Ranges API found. Last error: " + (lastErr ? lastErr.toString() : "(none)"));
}

function _readMemory(address, size) {
  // Defensive: handle multiple Frida variants for reading memory.
  var ptrAddr = ptr(address);

  // 1) Preferred: Memory.readByteArray(ptr, size)
  try {
    if (typeof Memory.readByteArray === 'function') {
      return Memory.readByteArray(ptrAddr, size);
    }
  } catch (e) {
    // fallthrough to other options
  }

  // 2) Pointer variant: ptr(address).readByteArray(size)
  try {
    if (ptrAddr && typeof ptrAddr.readByteArray === 'function') {
      return ptrAddr.readByteArray(size);
    }
  } catch (e) {
    // fallthrough
  }

  // 3) Fallback: read byte-by-byte into a Uint8Array and return ArrayBuffer
  try {
    var length = parseInt(size, 10);
    if (isNaN(length) || length <= 0) {
      return new ArrayBuffer(0);
    }
    var arr = new Uint8Array(length);
    for (var i = 0; i < length; i++) {
      // readU8 is widely available
      arr[i] = ptrAddr.add(i).readU8();
    }
    return arr.buffer;
  } catch (e) {
    // If everything fails, throw to allow Python side to understand read failed
    throw new Error("Failed to read memory at " + address + " size " + size + ": " + e);
  }
}

rpc.exports = {
  // enumerate - provide multiple exported names to match various caller styles
  enumerateRanges: function (prot) { return _enumRanges(prot); },
  enumerateranges: function (prot) { return _enumRanges(prot); },
  enumerate_ranges: function (prot) { return _enumRanges(prot); },

  // read - provide multiple exported names
  readMemory: function (address, size) { return _readMemory(address, size); },
  readmemory: function (address, size) { return _readMemory(address, size); },
  read_memory: function (address, size) { return _readMemory(address, size); }
};
"""


script = session.create_script(js_agent)
script.on("message", on_message)
script.load()

agent = script.exports_sync

# Try calling a few possible method names (first one that works will be used)
ranges = None
for fn_name in ("enumerateRanges", "enumerateranges", "enumerate_ranges"):
    try:
        func = getattr(agent, fn_name)
    except Exception:
        func = None
    if func:
        try:
            ranges = func(PERMS)
            break
        except Exception as e:
            print(f"enumeration attempt using '{fn_name}' failed: {e}")
            ranges = None

if ranges is None:
    print("Failed to enumerate ranges via Frida agent: no working RPC export found.")
    sys.exit(1)


# Helper to normalize addresses/sizes into integers
def _to_int_addr(a):
    try:
        # If it's already an int
        if isinstance(a, int):
            return a
        # Strings: possibly like "0x7ff..." or decimal
        if isinstance(a, str):
            s = a.strip()
            if s.startswith(("0x", "0X")):
                return int(s, 16)
            return int(s)
        # If it's a dict-like object (e.g. { "base": "0x..." }) handle elsewhere
        return int(a)
    except Exception:
        s = str(a).strip()
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        # try float fallback
        return int(float(s))


if arguments.max_size is not None:
    MAX_SIZE = arguments.max_size

i = 0
l = len(ranges)

# Performing the memory dump
for r in ranges:
    # support different field names returned by different Frida versions
    base_raw = None
    for key in ("base", "baseAddress", "address", "start"):
        if isinstance(r, dict) and key in r:
            base_raw = r[key]
            break
    size_raw = None
    for key in ("size", "length", "lengthInBytes"):
        if isinstance(r, dict) and key in r:
            size_raw = r[key]
            break

    if base_raw is None or size_raw is None:
        # fall back: maybe r itself is a (base, size) tuple/list
        if isinstance(r, (list, tuple)) and len(r) >= 2:
            base_raw = r[0]
            size_raw = r[1]
        else:
            logging.debug("Skipping malformed range entry: %s", r)
            continue

    try:
        base_addr = _to_int_addr(base_raw)
        size = _to_int_addr(size_raw)
    except Exception as e:
        logging.debug("Unable to parse base/size for range %s: %s", r, e)
        continue

    logging.debug("Range object: %s", r)
    logging.debug("Base Address: 0x%X", base_addr)
    logging.debug("Size: %d", size)

    if size > MAX_SIZE:
        logging.debug("Too big, splitting the dump into chunks")
        mem_access_viol = dumper.splitter(
            agent, base_addr, size, MAX_SIZE, mem_access_viol, DIRECTORY)
        continue
    mem_access_viol = dumper.dump_to_file(
        agent, base_addr, size, mem_access_viol, DIRECTORY)
    i += 1
    utils.printProgress(i, l, prefix='Progress:', suffix='Complete', bar=50)

# Run Strings if selected
if STRINGS:
    files = os.listdir(DIRECTORY)
    i = 0
    l = len(files)
    print("Running strings on all files:")
    for f1 in files:
        utils.strings(f1, DIRECTORY)
        i += 1
        utils.printProgress(i, l, prefix='Progress:',
                            suffix='Complete', bar=50)
print("Finished!")
# raw_input('Press Enter to exit...')
