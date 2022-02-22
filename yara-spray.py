#!/bin/python3

# Author: Gerald (geraldlim619@gmail.com)

import pathlib
import sys
import logging
import subprocess as sp
import datetime
import re
from glob import glob
import os
import argparse

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    DEBUG = '\033[93m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

os.makedirs(os.path.dirname('./log/yara-spray.log'), exist_ok=True)
logging.basicConfig(filename='./log/yara-spray.log', filemode='w', format='%(levelname)s - %(message)s')
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

DOTTED_LINE = "------------------------------------------------------------------------------------------------------\n"

def printMatchesList(matches_list):
    for match in matches_list:
        print(str(match))

def init_all_list(listPathsToSpray):
    extensions = ['.txt', '.log*', '.json', '.csv']

    print(bcolors.DEBUG + "[DEBUG] Initializing .txt list..." + bcolors.ENDC)
    print(bcolors.DEBUG + "[DEBUG] Initializing .log* list..." + bcolors.ENDC)
    print(bcolors.DEBUG + "[DEBUG] Initializing .json list..." + bcolors.ENDC)
    print(bcolors.DEBUG + "[DEBUG] Initializing .csv list..." + bcolors.ENDC)
    logger.debug("Initializing .txt list...")
    logger.debug("Initializing .log* list...")
    logger.debug("Initializing .json list...")
    logger.debug("Initializing .csv list...")
    matches_list = []
    for path in listPathsToSpray:
        print(bcolors.DEBUG + "\t---> Fetching from " + path + bcolors.ENDC)
        logger.debug("\t---> Fetching from " + path)
        for extension in extensions:
            matches_list.extend(pathlib.Path(path).glob("**/*"+extension))

    return sorted(matches_list)


def show_progress(fileIdx, totalFiles):
    fileIdx = float(fileIdx)
    return fileIdx/totalFiles * 100

def yara_scan(matches_list, yaraRule, yaraOutputPath):

    os.makedirs(os.path.dirname(yaraOutputPath), exist_ok=True)

    f = open(yaraOutputPath, 'w')
    fileIdx = 1
    totalFiles = len(matches_list)
    for file in matches_list:
        print("Current Progress: " + str(show_progress(fileIdx, totalFiles)) + "%")
        print(bcolors.OKGREEN + "[INFO] Scanning " + str(file) + "\n" + bcolors.ENDC)
        logger.info("Scanning " + str(file) + "\n")
        command = "./dependencies/yara -c " + str(yaraRule) + " \"" + str(file) + "\""  # number of hits
        f.write(DOTTED_LINE)
        f.write("#" + str(fileIdx) + " File Scanned: " + str(file) + "\n")
        f.write("Number of rule hits: " + str(sp.getoutput(command)) + "\n")
        command = "./dependencies/yara -s " + str(yaraRule) + " \"" + str(file) + "\""
        f.write(sp.getoutput(command)+"\n")
        f.flush()
        fileIdx += 1
    f.close()
    return


def main():

    parser = argparse.ArgumentParser(description='Perfoms a yara scan on directories containing [.csv, .txt, .json, .log*] files',
            epilog='Example:\n'+sys.argv[0]+' --dirs /home/gerald/extracts/ /home/gerald/json/ /other/dir/to/scan/ --rule ./rule/jndi-detect.yar --output ./output/2022-02-14-output.txt')
    parser.add_argument('--dirs', dest='dirs', metavar='', nargs='+', type=str, required=True, help='specify the full directory paths you wish to recursively scan using yara.')
    parser.add_argument('--rule', dest='rule', metavar='', type=str, required=True, help='specify the path of the yara rule you wish to apply')
    parser.add_argument('--output', dest='output', metavar='', type=str, required=True, help='specify the path of the yara output file') 
    parser.add_argument('--overwrite', dest='overwrite', action='store_true', help='(optional) Overwrites any existing folder')
    parser.set_defaults(overwrite=False)
    args = parser.parse_args()
    
    yaraRule = args.rule
    yaraOutputPath = args.output
    if os.path.exists(yaraOutputPath) and not args.overwrite:
        print(bcolors.WARNING + "[WARNING] Please provide a new yara output file to avoid accidental overwrites to the previous yara spray. Use --overwrite to ignore this warning." + bcolors.ENDC)
        return
    
    if not os.path.exists(yaraRule):
        print(bcolors.FAIL + "[FAIL] Yara rule not found!" + bcolors.ENDC)
        return

    listPathsToSpray = args.dirs
    matches_list = init_all_list(listPathsToSpray)

    yara_scan(matches_list, yaraRule, yaraOutputPath)
    print(bcolors.OKCYAN + "Yara scan done for all (.json, .log*, .csv, .txt) files" + bcolors.ENDC)
    print(bcolors.OKCYAN + "Please check " + yaraOutputPath + " for results!" + bcolors.ENDC)
    logger.info("Finished yara scan for all (.json, .log*, .csv, .txt) files")
    logger.info("Please check " + yaraOutputPath + " for results!")


if __name__ == "__main__":
    main()
