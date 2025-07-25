import logging
import argparse
import sys
import os
import pathlib
import zipfile
import tarfile
import gzip
import lzma
import shutil
import re

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
        except PermissionError as e:
            log.error(f"Unable to create log file: {e}")
            exit(1)
    return
    
def check_user_args() -> None:
    if not os.path.exists(args.input_dir):
        log.error(f"Input directory '{args.input_dir}' does not exist!")
        exit(1)
    if not os.path.exists(args.output_dir):
        try:
            os.makedirs(args.output_dir)
        except PermissionError as e:
            log.error("Unable to create output directory: {e}")
            exit(1)
    else:
        if not args.force_overwrite:
            log.warning("Please provide a new directory to extract to in order to avoid accidental overwrites. Use -f to ignore this warning.")
            exit(1)
    return

def recursive_extraction(archive: str, 
                         extract_path: str,
                         remove_archive=False):
    
    if archive.endswith(".zip"):
        extract_zip(archive, extract_path, remove_archive)
    elif archive.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz")):
        extract_tar(archive, extract_path, remove_archive)
    elif archive.endswith(".gz"):
        extract_gz(archive, extract_path, remove_archive)
    elif archive.endswith(".xz"):
        extract_xz(archive, extract_path, remove_archive)

    for dirpath, _, files in os.walk(extract_path):
        for file in files:
            if re.search(archive_suffix_regex, file):
                archive = os.path.join(dirpath, file)
                recursive_extraction(archive, dirpath, True)
    return

def extract_zip(archive: str,
                extract_path: str,
                remove_archive=False) -> bool:
    try:
        log.debug(f"Extracting {archive} to {extract_path}")
        with zipfile.ZipFile(archive, 'r') as zfile:
            zfile.extractall(path=extract_path)
        if remove_archive:
            os.remove(archive)
    except zipfile.BadZipFile as e:
        log.warning(f"Failed to extract {archive}: {e}")
    except FileNotFoundError as e:
        log.warning(f"File does not exist: {e}")
    except PermissionError as e:
        log.warning(f"Permissions error: {e}")
        return
    return

def extract_tar(archive: str, 
                extract_path: str, 
                remove_archive=False):
    try:
        log.debug(f"Extracting {archive} to {extract_path}")
        with tarfile.open(archive, 'r:*') as tfile:
            # In regards to CVE-2007-4559 Patch
            # See https://docs.python.org/3.12/library/tarfile.html#tarfile-extraction-filter
            tfile.extractall(path=extract_path, filter="tar")
        if remove_archive:
            os.remove(archive)
    except tarfile.TarError as e:
        log.warning(f"Failed to extract {archive}: {e}")
    except FileNotFoundError as e:
        log.warning(f"File does not exist: {e}")
    except PermissionError as e:
        log.warning(f"Permissions error: {e}")
    return

def extract_gz(archive: str,
               extract_path: str,
               remove_archive=False):
    
    archive_name = os.path.basename(archive)
    extract_path = os.path.join(extract_path, re.sub(r"\.gz$", "", archive_name))

    try:
        log.debug(f"Extracting {archive} to {extract_path}")
        f_in = gzip.open(archive, "rb")
        f_out = open(extract_path, "wb")
        shutil.copyfileobj(f_in, f_out)
        if remove_archive:
            os.remove(archive)
    except gzip.BadGzipFile as e:
        log.warning(f"Unable to decompress GZ file: {e}")
    except FileNotFoundError as e:
        log.warning(f"File does not exist: {e}")
    except PermissionError as e:
        log.warning(f"Permissions error: {e}")
    return
    
def extract_xz(archive: str,
               extract_path: str,
               remove_archive=False):
    
    archive_name = os.path.basename(archive)
    extract_path = os.path.join(extract_path, re.sub(r"\.xz$", "", archive_name))

    try:
        log.debug(f"Extracting {archive} to {extract_path}")
        f_in = lzma.open(archive, 'rb')
        f_out = open(extract_path, 'wb')
        shutil.copyfileobj(f_in, f_out)
        if remove_archive:
            os.remove(archive)
    except lzma.LZMAError as e:
        log.warning(f"Unable to decompress XZ file: {e}")
    except FileNotFoundError as e:
        log.warning(f"File does not exist: {e}")
    except PermissionError as e:
        log.warning(f"Permissions error: {e}")
    return

def main():
    log.info("Starting extraction...")
    archives = [
        str(p) for p in pathlib.Path(args.input_dir).rglob("*")
        if p.is_file() and re.search(archive_suffix_regex, p.name)
    ]

    log.debug(f"Found {archives}")
    for archive in archives:
        recursive_extraction(archive=archive, extract_path=args.output_dir)
    log.info(f"Finished extraction! Please check under '{args.output_dir}'")
    return

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Recursively extracts (nested) compressed logs while keeping original directory tree.')
    parser.add_argument("-i", "--input-dir", dest="input_dir", metavar="", type=str, required=True, help='The directory containing compressed logs')
    parser.add_argument("-o", "--output-dir", dest="output_dir", metavar="", type=str, required=True, help='The directory to extract to')
    parser.add_argument("-f", '--force-overwrite', dest='force_overwrite', action='store_true', help='Force extract to an existing directory.')
    parser.add_argument("-v", '--verbose', dest='verbose', action='store_true', help='Show debug logs')
    parser.add_argument("-l", "--log-file", dest="log_file", metavar="", type=str, required=False, help='Log the progress to a file')
    parser.set_defaults(force_overwrite=False)
    parser.set_defaults(verbose=False)
    args = parser.parse_args()

    log = logging.getLogger()
    init_logging(log_filepath=args.log_file, verbose=args.verbose)
    check_user_args()

    archive_suffix_regex = re.compile(r'\.(zip|tar|tar\.gz|tgz|tar\.xz|txz|gz|xz)$')
    main()
