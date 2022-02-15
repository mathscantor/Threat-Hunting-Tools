# Threat-Hunting-Tools
Tools to help facilitate workflow during threat hunting

First script to run would be logs-extractor.py
Server Admins often would give logs in archived form (.zip, .tar, .tar.gz etc.) and this script helps to automate the process of extraction into a specified folder.


kali@kali:~/Desktop/Threat-Hunting-Tools$ ./logs-extractor.py --help  
usage: logs-extractor.py [-h] --archive  --extract-to  [--overwrite]

Extracts (nested) .zip and (nested) .tar* logs

optional arguments:  
  -h, --help     show this help message and exit  
  --archive      specify the /full/path/to/archive/  
  --extract-to   specify the /full/path/to/extract/to/  
  --overwrite    (optional) Overwrites any existing folder  

Example: ./logs-extractor.py --archive /media/csl/storage/TECHNET/Dec2021/ --extract-to /home/gerald/extracts/



------------------------------------------------------------------------------------------------------------------------------------------------------------------
Second script to run would be evtx-converter.py
Windows Servers would contain many Windows Event Logs that needs to be converted to json for readability and for yara scanning later on.


kali@kali:~/Desktop/Threat-Hunting-Tools$ ./evtx-converter.py --help
usage: evtx-converter.py [-h] --target-dir  --dest-dir  [--overwrite]

Converts Windows Event Logs(.evtx) to json using evtxdump

optional arguments:
  -h, --help     show this help message and exit
  --target-dir   specify the /full/path/to/target/dir/ containing .evtx files.
  --dest-dir     specify the /full/path/to/dest/dir/ that you want the json files to be stored under.
  --overwrite    (optional) Overwrites any existing folder
  
Example: ./evtx-converter.py --target-dir /home/gerald/extracts/ --dest-dir /home/gerald/json/

------------------------------------------------------------------------------------------------------------------------------------------------------------------
Last script to run would be yara-spray.py
This is just a lazy way to recursively perform a yara scan with a specified yara rule on all directories you supply recursively. And writes yara results to an
output file.


kali@kali:~/Desktop/Threat-Hunting-Tools$ ./yara-spray.py --help
usage: yara-spray.py [-h] --dirs  [...] --rule  --output  [--overwrite]

Perfoms a yara scan on directories containing [.csv, .txt, .json, .log*] files

optional arguments:
  -h, --help      show this help message and exit
  --dirs  [ ...]  specify the full directory paths you wish to recursively scan using yara.
  --rule          specify the path of the yara rule you wish to apply
  --output        specify the path of the yara output file
  --overwrite     (optional) Overwrites any existing folder

Example: ./yara-spray.py --dirs /home/gerald/extracts/ /home/gerald/json/ /other/dir/to/scan/ --rule ./rule/jndi-detect.yar --output ./output/2022-02-14-output.txt
