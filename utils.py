import sys
import logging
import os
import re

# Progress bar function
def printProgress(times, total, prefix='', suffix='', decimals=2, bar=100):
    if total == 0:
        return
    filled = int(round(bar * times / float(total)))
    percents = round(100.00 * (times / float(total)), decimals)
    bar_str = '#' * filled + '-' * (bar - filled)
    sys.stdout.write('%s [%s] %s%s %s\r' %
                     (prefix, bar_str, percents, '%', suffix))
    sys.stdout.flush()
    if times == total:
        print("\n")


# A very basic implementations of Strings
def strings(filename, directory, min=4):
    strings_file = os.path.join(directory, "strings.txt")
    path = os.path.join(directory, filename)
    try:
        with open(path, encoding='Latin-1', errors='ignore') as infile:
            str_list = re.findall(r"[A-Za-z0-9/\-:;.,_$%'!()\[\]<> \#]+", infile.read())
            with open(strings_file, "a", encoding='utf-8') as st:
                for s in str_list:
                    if len(s) > min:
                        logging.debug(s)
                        st.write(s + "\n")
    except Exception as e:
        logging.debug("strings() failed on %s: %s", path, e)

# Normalize the name of application works better on frida
def normalize_app_name(appName=str):
    try:
        appName = int(appName)
    except Exception:
        pass
    return appName
