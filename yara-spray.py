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
import json

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

def yara_scan(scan_target: str) -> bool:

    try:
        log.info(f"Scanning '{scan_target}'")
        # TODO
        # -w to disable warning
        # eg. ./bin/x86_64/linux/yara scan -w -s ./tests/yara-spray/log4j.yar ./tests/yara-spray/test.log
        # proc = subprocess.Popen([bin_path, "scan", "-w", "-s", args.yara_rule, scan_target])
        proc = subprocess.Popen([bin_path, "scan", "-w", "-s", "--output-format", "ndjson", args.yara_rule, scan_target], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = proc.communicate()

        try:
            json_result = json.loads(stdout.decode('utf-8').strip())
        except json.JSONDecodeError as e:
            log.warning(f"Failed to decode json: {e}")
            return False
        
        return_code = proc.returncode
        if return_code != 0:
            log.warning(f"Unable to scan {scan_target}")
            return False
        
        # If there are no results, just end the post-processing and return True.
        if len(json_result["rules"]) == 0:
            return True
        
        with update_unique_results_lock:
            results.append(json_result)

    except subprocess.CalledProcessError as e:
        log.warning(f"Failed to run '{bin_path}': {e}")
    except PermissionError as e:
        log.error(f"Unable to run '{bin_path}': {e}")
        exit(1)

    return True

def get_formatted_results() -> str:

    table = f"{'Log Path':<30} {'Rule':<45} {'String ID':<10} {'Offset':<10} {'Match'}\n"
    table += "-" * 150 + "\n"

    # Print rows
    for result in results:
        path = result['path']
        for rule in result['rules']:
            rule_id = rule['identifier']
            for string in rule['strings']:
                table += f"{path:<30} {rule_id:<45} {string['identifier']:<10} {hex(string['offset']):<10} {string['match']}\n"

    return table

def worker_task() -> None:
    while (True):
        with get_log_lock:
            # log.debug(f"Remaining: {logs}")
            if not scan_targets:
                break
            scan_target = scan_targets.popleft()
        yara_scan(scan_target)
    return

def main():
    start_time = time.time()
    log.info(f"Starting yara spray with rule: {args.yara_rule}")
    for _ in range(args.threads):
        worker = threading.Thread(target=worker_task)
        threads.append(worker)
        worker.start()

    for thread in threads:
        thread.join()

    end_time = time.time()
    total_time = end_time - start_time
    log.info(f"Results:\n{get_formatted_results()}")
    log.info(f"Finished yara spray in {total_time:.5f}s!")
    return

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Yara scan on all logs from a given directory',
                                     epilog="Credits: https://github.com/VirusTotal/yara-x")
    
    parser.add_argument("-i", "--input-dir", dest="input_dir", metavar="", type=str, required=True, help='The directory containing EVTX logs')
    parser.add_argument("-y", "--yara-rule", dest="yara_rule", metavar="", type=str, required=True, help='The yara rule file.')
    parser.add_argument("-j", "--threads", dest="threads", metavar="", type=int, required=False, help='The number of threads used for extraction (default: 1)')
    parser.add_argument("-f", '--force', dest='force_overwrite', action='store_true', help='Forcefully write serialized logs to non-empty directory')
    parser.add_argument("-v", '--verbose', dest='verbose', action='store_true', help='Show debug logs')
    parser.add_argument("-l", "--log-file", dest="log_file", metavar="", type=str, required=False, help='Log the progress to a file')
    parser.set_defaults(threads=1)
    parser.set_defaults(force_overwrite=False)
    parser.set_defaults(verbose=False)
    args = parser.parse_args()

    log = logging.getLogger()
    init_logging(log_filepath=args.log_file, verbose=args.verbose)
    check_user_args()

    # Globals
    scan_target_suffix_regex = re.compile(r"\.(log|txt|out|err|report|trace|dump|xml|json|jsonl|ndjson)(\.\d+)?$", re.IGNORECASE)
    scan_targets = deque([
        str(p) for p in pathlib.Path(args.input_dir).rglob("*")
        if p.is_file() and re.search(scan_target_suffix_regex, p.name)
    ])

    arch, os_name = get_arch_and_os()
    if os_name == "windows":
        bin_path = f"./bin/{arch}/{os_name}/yara.exe"
    else:
        bin_path = f"./bin/{arch}/{os_name}/yara"
    os.chmod(bin_path, os.stat(bin_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    get_log_lock = threading.Lock()
    update_unique_results_lock = threading.Lock()
    threads = list()

    results = list()
    main()