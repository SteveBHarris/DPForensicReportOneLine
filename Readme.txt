#DefensePro forensic with details to one line
#Date Created: 14 March 2024
#Last Updated: 15 March 2024
#version 1.0

# Owner/Maintainer

	Steve Harris - Steven.Harris@radware.com

# About

	This script parses a directory full of DefensePro Forensic Report .csv files. It will take the multiline default format and convert it to a single line per event. It combines Source IP, Destination, IP, Ports, etc, removes duplicates and sorts them within their cell.

	Input: Place .csv files in the .\input\ folder. 
	Output: .\output\<input filename>.xlsx
	
#Prerequesites
	Requires the openpyxl library. 'pip install openpyxl' to download.
	
# How to run

	1. Place DefensePro Forensic Report .csv files into the .\input\ folder
	2. Run the script
		python DPForensicReportOneLine.py
	3. View the output files under .\output\<filename>.xlsx

	Note: The DefensePro will occasionally produce corrupt entries in the report.csv file. This script handles them as best it can. The word 'err' will be inserted in the beginning of the first column when an error is detected in that line.
	
# Version control

V1.0.0 - Initial Release
