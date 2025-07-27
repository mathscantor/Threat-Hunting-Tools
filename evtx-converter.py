import logging
import argparse
import sys
import os
import pathlib
import re
import threading
from collections import deque
import time
import subprocess
from typing import Tuple
import platform
import sys
import stat

def init_logging(verbose: bool=False,
                 log_filepath: str=None) -> None:
    
    log_formatter = logging.Formatter("%(asctime)s [%(threadName)s] [%(funcName)s] [%(levelname)s] %(message)s")
    if verbose:
        log.setLevel(logging.DEBUG)
    else:
        log.setLevel(logging.INFO)

    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(log_formatter)
    log.addHandler(consoleHandler)

    if log_filepath is not None:
        try:
            os.makedirs(os.path.dirname(log_filepath), exist_ok=True)
            log_filehandler = logging.FileHandler(log_filepath)
            log_filehandler.setFormatter(log_formatter)
            log.addHandler(log_filehandler)
        except Exception as e:
            log.error(f"Unable to create log file: {e}")
            exit(1)
    return
    
def check_user_args() -> None:

    # Check input directory
    if not os.path.exists(args.input_dir):
        log.error(f"Input directory '{args.input_dir}' does not exist!")
        exit(1)
    else:
        if not os.path.isdir(args.input_dir):
            log.error("Stated input directory is not a directory!")
            exit(1)

    # Check output directory
    if not os.path.exists(args.output_dir):
        try:
            os.makedirs(args.output_dir)
        except PermissionError as e:
            log.error("Unable to create output directory: {e}")
            exit(1)
    else:
        if not os.path.isdir(args.output_dir):
            log.error("Stated output directory is not a directory!")
            exit(1)
        elif os.listdir(args.output_dir) and not args.force_overwrite:
            log.warning(f"Directory {args.output_dir} is not empty. Use -f to ignore this warning.")
            exit(1)
    return

def get_arch_and_os() -> Tuple[str, str]:
    arch = platform.machine().lower()
    os_name = sys.platform

    if arch in ["x86_64", "amd64"]:
        arch = "x86_64"
    elif arch in ["aarch64", "arm64"]:
        arch = "aarch64"
    else:
        log.error(f"This architecture ({arch}) is not supported!")
        exit(1)

    if os_name.startswith("linux"):
        os_name = "linux"
    elif os_name.startswith("win"):
        os_name = "windows"
    elif os_name.startswith("darwin"):
        os_name = "macos"
    else:
        log.error(f"This OS ({os_name}) is not supported!")
        exit(1)

    # Hardcoded edge case here
    # Currently, I cannot figure out how to statically cross compile an aarch64 windows binary using cargo.
    if os_name == "windows" and arch == "aarch64":
        log.error(f"Apologies, my friend. My potato brain hasn't figure out how to cross compile an aarch64 windows binary using cargo. A PR here will be much appreciated!")
        exit(1)

    return arch, os_name

def convert_evtx(winevent_log: str,
                 convert_path: str,
                 format: str) -> None:

    try:
        log.info(f"Converting '{winevent_log}'")
        subprocess.Popen([bin_path, winevent_log, "-o", format, "-f", convert_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        log.warning(f"Failed to run '{bin_path}': {e}")
    except PermissionError as e:
        log.error(f"Unable to run '{bin_path}': {e}")
        exit(1)
    return

def worker_task() -> None:
    while (True):
        with read_evtx_lock:
            # log.debug(f"Remaining: {winevent_logs}")
            if not winevent_logs:
                break
            winevent_log = winevent_logs.popleft()
        leaf_dirname = os.path.basename(os.path.dirname(winevent_log))
        convert_path = os.path.join(args.output_dir, leaf_dirname, f"{os.path.basename(winevent_log[:-5])}.{args.format}")
        convert_evtx(winevent_log, convert_path, args.format)
    return

def main():
    start_time = time.time()
    log.info("Starting EVTX conversion")
    for _ in range(args.threads):
        worker = threading.Thread(target=worker_task)
        threads.append(worker)
        worker.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    total_time = end_time - start_time
    log.info(f"Finished conversion in {total_time:.5f}s! Please check under '{args.output_dir}'")
    return

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='EVTX conversion is based on evtx_dump utility',
                                     epilog="Credits: https://github.com/omerbenamram/evtx")
    
    allowed_formats = ["jsonl", "json", "xml"]

    parser.add_argument("-i", "--input-dir", dest="input_dir", metavar="", type=str, required=True, help='The directory containing EVTX logs')
    parser.add_argument("-o", "--output-dir", dest="output_dir", metavar="", type=str, required=True, help='The directory to store the serialized logs')
    parser.add_argument("-j", "--threads", dest="threads", metavar="", type=int, required=False, help='The number of threads used for extraction (default: 1)')
    parser.add_argument("-t", "--format", dest="format", metavar="", choices=allowed_formats, type=str, required=False, help='The format of the serialized logs: [jsonl(default), json, xml]')
    parser.add_argument("-f", '--force', dest='force_overwrite', action='store_true', help='Forcefully write serialized logs to non-empty directory')
    parser.add_argument("-v", '--verbose', dest='verbose', action='store_true', help='Show debug logs')
    parser.add_argument("-l", "--log-file", dest="log_file", metavar="", type=str, required=False, help='Log the progress to a file')
    parser.set_defaults(threads=1)
    parser.set_defaults(force_overwrite=False)
    parser.set_defaults(verbose=False)
    parser.set_defaults(format=allowed_formats[0])
    args = parser.parse_args()

    log = logging.getLogger()
    init_logging(log_filepath=args.log_file, verbose=args.verbose)
    check_user_args()

    # Globals
    winevent_suffix_regex = re.compile(r'\.evtx$')
    winevent_logs = deque([
        str(p) for p in pathlib.Path(args.input_dir).rglob("*")
        if p.is_file() and re.search(winevent_suffix_regex, p.name)
    ])

    arch, os_name = get_arch_and_os()
    if os_name == "windows":
        bin_path = f"./bin/{arch}/{os_name}/evtx_dump.exe"
    else:
        bin_path = f"./bin/{arch}/{os_name}/evtx_dump"
    os.chmod(bin_path, os.stat(bin_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    read_evtx_lock = threading.Lock()
    threads = list()
    main()