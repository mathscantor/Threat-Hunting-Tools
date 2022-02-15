#!/bin/python3

#Author: Gerald (geraldlim619@gmail.com)

import zipfile
import os
import pathlib
import sys
import logging
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

os.makedirs(os.path.dirname('./log/evtx-converter.log'), exist_ok=True)
logging.basicConfig(filename='./log/evtx-converter.log', filemode='w', format='%(levelname)s - %(message)s')
logger=logging.getLogger()
logger.setLevel(logging.DEBUG)

def printMatchesList(matches_list):
    for match in matches_list:
        print(str(match))

def show_progress(fileIdx, totalFiles):
    fileIdx = float(fileIdx)
    return fileIdx/totalFiles * 100

def main():

    parser = argparse.ArgumentParser(description='Converts Windows Event Logs(.evtx) to json using evtxdump',
            epilog='Example:\n'+sys.argv[0]+' --target-dir /home/gerald/extracts/ --dest-dir /home/gerald/json/')
    parser.add_argument('--target-dir', dest='targetDir', metavar='', type=str, required=True, help='specify the /full/path/to/target/dir/ containing .evtx files.')
    parser.add_argument('--dest-dir', dest='destDir', metavar='', type=str, required=True, help='specify the /full/path/to/dest/dir/ that you want the json files to be stored under.')
    parser.add_argument('--overwrite', dest='overwrite', action='store_true', help='(optional) Overwrites any existing folder')
    parser.set_defaults(overwrite=False)
    args = parser.parse_args()
    
    print(args.destDir)

    if os.path.exists(args.destDir) and not args.overwrite:
        print(bcolors.WARNING + "[WARNING] Please provide a new destination directory to avoid accidental overwrites. Use --overwrite to ignore this warning." + bcolors.ENDC)
        return
    
    

    extractedLogsDir = args.targetDir
    convertedEvtxDir = args.destDir

    matches = pathlib.Path(extractedLogsDir).glob("**/*.evtx")
    matches_list = sorted(matches)
    totalFiles = len(matches_list)
    fileIdx = 1
    for match in matches_list:
        convertedFilesPath = convertedEvtxDir + str(match).replace(extractedLogsDir, "").replace(".evtx", ".json")
        print("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")
        logger.info("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")  
        fileIdx += 1
        try:
            print(bcolors.OKGREEN + "[INFO] Converting " + str(match) + " to " + convertedFilesPath + "\n" + bcolors.ENDC)
            logger.info("Converting " + str(match) + " to " + convertedFilesPath +"\n")
            os.system("./dependencies/evtxdump --dont-show-record-number --no-confirm-overwrite --format json --output \"{0}\" \"{1}\"".format(convertedFilesPath,str(match)))
        except:
            print("Error converting {0}".format(str(match)))
            logger.error("Error converting " + str(match))

    print(bcolors.OKCYAN + "Finished converting all evtx files to json files!" + bcolors.ENDC)
    print(bcolors.OKCYAN + "Please check " + convertedEvtxDir + " for json files!" + bcolors.ENDC)
    logger.info("Finished converting all evtx files to json files!")
    logger.info("Please check " + convertedEvtxDir + " for json files!")

if __name__ == "__main__":
    main()


