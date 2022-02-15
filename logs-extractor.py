#!/bin/python3

#Author: Gerald (geraldlim619@gmail.com)

import zipfile
import os
import pathlib
import sys
import logging
import tarfile
import gzip
import argparse


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

os.makedirs(os.path.dirname('./log/logs-extractor.log'), exist_ok=True)
logging.basicConfig(filename='./log/logs-extractor.log', filemode='w', format='%(levelname)s - %(message)s')
logger=logging.getLogger()
logger.setLevel(logging.DEBUG)

def printMatchesList(matches_list):
    for match in matches_list:
        print(str(match))


def extract_nested_zip(zippedFile, toFolder, removeZip=False):
    try:
        with zipfile.ZipFile(zippedFile, 'r') as zfile:
            print(bcolors.OKGREEN + "[INFO] Extracting " + zippedFile + " to " + toFolder + "\n" + bcolors.ENDC)
            logger.info("Extracting " + zippedFile + " to " + toFolder + "\n")
            zfile.extractall(path=toFolder)
        if removeZip:
            os.remove(zippedFile)
    except:
        print(bcolors.WARNING + "[WARNING] Failed to extract {0}".format(zippedFile) + bcolors.ENDC)
        logger.warning("Failed to extract " + zippedFile)
        return

    for root, dirs, files in os.walk(toFolder):
        for filename in files:
            if filename.endswith(".zip"):
                dest = os.path.join(root, filename[:-4])
                fileSpec = os.path.join(root, filename)
                extract_nested_zip(fileSpec, dest, True)


def extract_nested_tar(tarFile, toFolder, removeTar=False):
    try:
        with tarfile.open(tarFile, 'r') as tfile:
            print(bcolors.OKGREEN + "[INFO] Extracting " + tarFile + " to " + toFolder + "\n" + bcolors.ENDC)
            logger.info("Extracting " + tarFile + " to " + toFolder + "\n")
            tfile.extractall(path=toFolder)
        if removeTar:
            os.remove(tarFile)
    except:
        print(bcolors.WARNING + "[WARNING] Failed to extract {0}".format(tarFile) + bcolors.ENDC)
        logger.warning("Failed to extract " + tarFile)
        return

    for root, dirs, files in os.walk(toFolder):
        for filename in files:
            if filename.endswith(".tar.gz"):
                dest = os.path.join(root, filename[:-7])
                fileSpec = os.path.join(root, filename)
                extract_nested_tar(fileSpec, dest, True)
            elif filename.endswith(".tar"):
                dest = os.path.join(root, filename[:-4])
                fileSpec = os.path.join(root, filename)
                extract_nested_tar(fileSpec, dest, True)

def show_progress(fileIdx, totalFiles):
    fileIdx = float(fileIdx)
    return fileIdx/totalFiles * 100

def main():

    parser = argparse.ArgumentParser(description='Extracts (nested) .zip and (nested) .tar* logs',
            epilog='Example:\n'+sys.argv[0]+' --archive /media/csl/storage/TECHNET/Dec2021/ --extract-to /home/gerald/extracts/')
    parser.add_argument('--archive', dest='archive', metavar='', type=str, required=True, help='specify the /full/path/to/archive/')
    parser.add_argument('--extract-to', dest='extractTo', metavar='', type=str, required=True, help='specify the /full/path/to/extract/to/')
    parser.add_argument('--overwrite', dest='overwrite', action='store_true', help='(optional) Overwrites any existing folder')
    parser.set_defaults(overwrite=False)
    args = parser.parse_args()

    if os.path.exists(args.extractTo) and not args.overwrite:
        print(bcolors.WARNING + "[WARNING] Please provide a new directory to extract to in order to avoid accidental overwrites. Use --overwrite to ignore this warning." + bcolors.ENDC)
        return


    parentLogsDirPath = args.archive
    extractedFilesDir = args.extractTo

    matches_zip = pathlib.Path(parentLogsDirPath).glob("**/*.zip")
    matches_zip_list = sorted(matches_zip)
    matches_tar = pathlib.Path(parentLogsDirPath).glob("**/*.tar*")
    matches_tar_list = sorted(matches_tar)

    totalFiles = len(matches_zip_list) + len(matches_tar_list)    
    fileIdx = 1
    for match_zip in matches_zip_list:
        print("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")
        logger.info("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")
        fileIdx += 1
        extractedFilesPath = extractedFilesDir + str(match_zip).replace(parentLogsDirPath, "").replace(".zip", "")
        extract_nested_zip(str(match_zip), extractedFilesPath)

    for match_tar in matches_tar_list:
        print("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")
        logger.info("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")
        fileIdx += 1
        extractedFilesPath = extractedFilesDir + str(match_tar).replace(parentLogsDirPath, "").replace(".tar", "").replace(".gz","")
        extract_nested_tar(str(match_tar), extractedFilesPath)


    print(bcolors.OKCYAN + "Finished Extracting all compressed files, including nested compressed files!" + bcolors.ENDC)
    print(bcolors.OKCYAN + "Please check " + extractedFilesDir + " for extracted files!" + bcolors.ENDC)
    logger.info("Finished Extracting all compressed files, including nested compressed files!")
    logger.info("Please check " + extractedFilesDir + " for extracted files!")


if __name__ == "__main__":
    main()

