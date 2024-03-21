#DefensePro forensic with details to one line
#Date Created: 14 March 2024
#Last Updated: 15 March 2024
#version 1.0

# Owner/Maintainer

	Steve Harris - Steven.Harris@radware.com

# About

	This script parses a directory full of DefensePro Forensic Report .csv files. It will take the multiline default format and convert it to a single line per event excel file excel file. It combines Source IP, Destination, IP, Ports, etc, removes duplicates and sorts them within their cell.

	Input: Place .csv files in the .\input\ folder. 
	Output: .\output\<input filename>.xlsx
	
#Prerequesites
	Requires the openpyxl library. 'pip install openpyxl' to download. 
	The script will instruct you to install this if it is missing.
	
# How to run

	1. Place DefensePro Forensic Report .csv files into the .\input\ folder
	2. Run the script
		python DPForensicReportOneLine.py
	3. View the output files under .\output\<filename>.xlsx

	Note: The DefensePro will occasionally produce corrupt entries in the report.csv file. This script handles them as best it can. The word 'err' will be inserted in the beginning of the first column when an error is detected in that line.
	
# Version control

V1.0.0 - Initial Release
	* 40 columns total.
	* Parses up to the default 26 header rows (S.No, Start Time, End Time, Device IP Address, Threat Category, Attack Name, Policy Name, Action, Attack ID, Source IP Address, Source Port, Destination IP Address, Destination Port, Direction, Protocol, Radware ID, Duration, Total Packets Dropped, Packet Type, Total Mbits Dropped, Max pps, Max bps, Physical Port, Risk, VLAN Tag, Footprint)
	* Parses and includes additional rows for Footprint, State, Source IP, Source Port, Destination IP, Destination Port
	* Parses and includes SAMPLE DETAILS: lines.
	* Auto adjusts width and height of cells.
	* Fills alternate cells with faint color for better readability.
	* Applies borders for better readability.

	Full list of output columns: S.No, Start Time, End Time, Device IP Address, Threat Category, Attack Name, Policy Name, Action, Attack ID, Source IP Address, Source Port, Destination IP Address, Destination Port, Direction, Protocol, Radware ID, Duration, Total Packets Dropped, Packet Type, Total Mbits Dropped, Max pps, Max bps, Physical Port, Risk, DetailFootprint, State, Source Port, Destination IP, Sample Source IPs, Sample Source Ports, Sample Dest IPs, Sample Dest Ports, Sample Physical Ports, Sample Protocol

	If you would like additional detail to be included in the output, please contact Steven.Harris@radware.com
	
# Error handling
	The DefensePro is not perfect at outputting this data. Occasionally entries in the .csv file will be out of order, overlap adjacent entries, or be missing critical data entirely. The script will do it's best to process the data as normal, but will add 'Err#' to the top of the column A cell for the row.
	Here is a list of error #s and what they indicate:
		Err1 - Multiple headers in same entry.
		Err2 - Header line is missing.
		Err3 - <2 lines in entry.
		Err4 - More headers than data.
		Err5 - Non-numeric data in column A. (Column A should always contain a S.No)
		
			* 40 columns total.
	* Parses up to the default 26 header rows (S.No, Start Time, End Time, Device IP Address, Threat Category, Attack Name, Policy Name, Action, Attack ID, Source IP Address, Source Port, Destination IP Address, Destination Port, Direction, Protocol, Radware ID, Duration, Total Packets Dropped, Packet Type, Total Mbits Dropped, Max pps, Max bps, Physical Port, Risk, VLAN Tag, Footprint)
	* Parses and includes additional rows for Footprint, State, Source IP, Source Port, Destination IP, Destination Port
	* Parses and includes SAMPLE DETAILS: lines.
	* Auto adjusts width and height of cells.
	* Fills alternate cells with faint color for better readability.
	* Applies borders for better readability.

	Full list of output columns: S.No, Start Time, End Time, Device IP Address, Threat Category, Attack Name, Policy Name, Action, Attack ID, Source IP Address, Source Port, Destination IP Address, Destination Port, Direction, Protocol, Radware ID, Duration, Total Packets Dropped, Packet Type, Total Mbits Dropped, Max pps, Max bps, Physical Port, Risk, DetailFootprint, State, Source Port, Destination IP, Sample Source IPs, Sample Source Ports, Sample Dest IPs, Sample Dest Ports, Sample Physical Ports, Sample Protocol

	If you would like additional detail to be included in the output, please contact Steven.Harris@radware.com
