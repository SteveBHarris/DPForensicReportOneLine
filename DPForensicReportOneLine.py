#DefensePro forensic with details to one line
#Created and maintained by Steve Harris - Steven.Harris@radware.com
#Date Created: 14 March 2024
#Last Updated: 15 March 2024
#version 1.0
import os
import csv
import io
import re
try:
    import openpyxl
except ImportError:
    print("openpyxl is not installed. Please install it by running: pip install openpyxl")
    exit()

input_path = "./input/"
output_path = "./output/"
replaceExistingFile = False
maxWidth=64
ColorAlternateRows = True
fillColor = 'F0F0F0F0'
hideEmptyColumns = True

def rowSearch(rowStr,entry):
    try:
        return re.search(rf'(\n{re.escape(rowStr)})(.+)',entry,re.MULTILINE).group(2)
    except:
        #rowStr not found.
        return(f'')

class clsEntry:
    def __init__(self,rawEntry):
        #Grab columns a-z from the second row of the entry
        self.first26 = []
        for i in range(26):
            self.first26.append('')
        lines = rawEntry.splitlines()
        headerCount = 0
        for line in lines:
            if line.startswith("S.No,"):
                headerCount += 1
        if headerCount > 1:
            print("Warning: Corrupt entry. Multiple headers in same entry.")
            self.first26[0] = "Err1"
            #self.first26[0] = "Multiple in same entry:"
        elif headerCount == 0:
            print("Warning: Corrupt entry. Header line is missing.")
            self.first26[0] = "Err2"
            #self.first26[0] = "Header line missing"
        if len(lines) < 2:
            print("Corrupt entry detected. <2 lines in entry.")
            self.error = "Err3"
            return
        
        allMetrics = ["S.No","Start Time","End Time","Device IP Address","Threat Category","Attack Name","Policy Name","Action","Attack ID","Source IP Address","Source Port","Destination IP Address","Destination Port","Direction","Protocol","Radware ID","Duration","Total Packets Dropped","Packet Type","Total Mbits Dropped","Max pps","Max bps","Physical Port","Risk","VLAN Tag","Footprint"]
        matches = re.findall(r'(^S.No,.*\n)(.*$)',rawEntry, re.MULTILINE)
        for match in matches:
            reader = csv.reader(io.StringIO(match[0]))
            headers = next(reader)
            reader = csv.reader(io.StringIO(match[1]))
            data = next(reader)
            if len(headers) > len(data): #We can't have more headers than entries
                print("Warning: More headers than data:")
                print(f'    Headers: {headers} \n Data: {data}')
                self.first26[0] = '\n'.join(["Err4",self.first26[0]]).strip() 
            try:
                if not data[0].isnumeric():
                    self.first26[0].value = 'Err5'
                    raise ValueError("Bad data")
                for i, header in enumerate(headers):
                    if data[i] != '':
                        index = allMetrics.index(header)
                        self.first26[index] = '\n'.join([self.first26[index],data[i]]).strip()
            except:
                print(f"Bad Data detected when parsing entry: Headers: {headers} Data: {data}")
        #Parse specific rows
        self.footprint = rowSearch("Footprint,",rawEntry).strip('"')
        self.state = rowSearch("State,",rawEntry)        
        self.sIP = rowSearch("Source IP,",rawEntry)
        #If we matched the header row of the SAMPLE DETAILS section, the entry does not contain source ips.
        if self.sIP.startswith(" Source Port,"):
            self.sIP = ''
        self.sPort = rowSearch("Source Port,",rawEntry)
        self.dIP = rowSearch("Destination IP,",rawEntry)
        self.dPort = rowSearch("Destination Port,",rawEntry)

        #Parse Sample Data. DOTALL is so '.' matches newline
        sampleMatch = re.search(r'(^SAMPLE DETAILS:(?:,*)\n)(.*)',rawEntry,re.MULTILINE | re.DOTALL)
        self.samples=[]
        if sampleMatch:
            sampleLines = sampleMatch.group(2).splitlines()

            #Iterate through sampleLines starting with line 2. Line 1 is a header.
            for sampleLine in sampleLines[1:]:
                reader = csv.reader(io.StringIO(sampleLine))
                self.samples.append(next(reader))
        #else:
        #    print(f"SAMPLE DETAILS not found for id: {self.first26[8]}")

def processData(rawData):
    #Initialize the workbook and sheet.
    wb = openpyxl.Workbook()
    sheet = wb.active

    #Create the header row
    headers = ["S.No",
        "Start Time",
        "End Time",
        "Device IP Address",
        "Threat Category",
        "Attack Name",
        "Policy Name",
        "Action",
        "Attack ID",
        "Source IP Address",
        "Source Port",
        "Destination IP Address",
        "Destination Port",
        "Direction",
        "Protocol",
        "Radware ID",
        "Duration",
        "Total Packets Dropped",
        "Packet Type",
        "Total Mbits Dropped",
        "Max pps",
        "Max bps",
        "Physical Port",
        "Risk",
        "VLAN Tag",
        "Footprint",
        "DetailFootprint",
        "State",
        "Source IP",
        "Source Port",
        "Destination IP",
        "Destination Port",
        "Sample Source IPs",
        "Sample Source Ports",
        "Sample Dest IPs",
        "Sample Dest Ports",
        "Sample Physical Ports",
        "Sample Vlan Tags",
        "Sample MPLS RD",
        "Sample Protocol"]
    sheet.append(headers)
    
    #Make the headers bold
    for cell in sheet["1:1"]:
        cell.font = openpyxl.styles.Font(bold=True)

    #Create an array of all entries in the input file.
    ##rawEntries = rawData.split("*********************************************************************\n")
    rawEntries = re.split(r'\n\*{69}(?:,*)\n',rawData)
    print(f"{len(rawEntries)} entries found.")
    #Loop through each item of the array, processing the data within and creating a row in our output sheet.
    curRow = 2
    for rawEntry in rawEntries:
        if len(rawEntry) > 1:
            #Populate entry with the desired data. See class clsEntry.
            entry = clsEntry(rawEntry)

            if hasattr(entry,'error'):
                sheet.cell(row=curRow,column=1).value = entry.error
                curRow += 1
                continue
            #For troubleshooting, enable the following rows:
            #print(f'Processing Attack ID: {entry.first26[8]} S.No: {entry.first26}')
            #print(f'=============\n{rawEntry}\n==================')

            #Populate the cells in our spreadsheet row.
            for curColumn in range(26): #Populate columns A-Z
                if entry.first26[curColumn]:
                    sheet.cell(row=curRow,column=curColumn + 1).value = entry.first26[curColumn]
            sheet.cell(row=curRow,column=27).value = entry.footprint
            sheet.cell(row=curRow,column=28).value = entry.state
            sheet.cell(row=curRow,column=29).value = entry.sIP
            sheet.cell(row=curRow,column=30).value = entry.sPort
            sheet.cell(row=curRow,column=31).value = entry.dIP
            sheet.cell(row=curRow,column=32).value = entry.dPort
            if len(entry.samples) > 0:
                for sample in entry.samples: 
                    for i in range(8):
                        if len(sample) >= i + 1:
                            if not sheet.cell(row=curRow,column=33+i).value:
                                sheet.cell(row=curRow,column=33+i).value = sample[i]
                            else:
                                sheet.cell(row=curRow,column=33+i).value += "\n" + sample[i]
                        else:
                            sheet.cell(row=curRow,column=33+i).value = '\n'.join(['Error',sheet.cell(row=curRow,column=33+i).value or '']).strip()
                #Remove duplicates from the samples we just added.
                for i in range(8):
                    curCell = sheet.cell(row=curRow,column=33+i)
                    curCell.value = '\n'.join(set(curCell.value.split('\n')))

            #Replace commas with newlines 
            for i in [29,30,31,32]:
                curCell = sheet.cell(row=curRow,column=i)
                curCell.value = '\n'.join(sorted(set(curCell.value.split(','))))

            #Sort multiline entries
            def custom_sort(item):
                if '.' in item: #IPv4
                    parts = item.split('.')
                    return [int(part) for part in parts]
                elif ':' in item: #IPv6
                    hextets = item.split(':')
                    if len(hextets) < 8:#Properly handle :: in ipv6 address
                        for index, value in enumerate(hextets):
                            if value == '':
                                hextets[index:index+1] = ['0'] * (9 - len(hextets))
                    
                    return [int(hextet,16) for hextet in hextets]
                elif item.isnumeric(): #Simple number
                    return [int(item)]
                else: #Text
                    return [1]
            for i in range(29,41):#[29,30,31,32,33,34,35,36,37,38,39,40]:
                curCell = sheet.cell(row=curRow,column=i)
                if curCell.value:
                    item = set(curCell.value.strip().split('\n'))
                    if len(item) > 1:
                        #print("---")
                        #print(curCell.value )
                        try:
                            curCell.value = '\n'.join(sorted(item, key=custom_sort))
                        except:
                            print(f"Error sorting column {i}")

            #Set all cells to Align top
            for i in range(1,41):
                sheet.cell(row=curRow,column=i).alignment = openpyxl.styles.Alignment(vertical='top')
            
            #Color alternate rows
            if ColorAlternateRows: #vairable set near at the top of the script
                if curRow % 2 == 0:
                    for i in range(1,41):
                        sheet.cell(row=curRow,column=i).fill = openpyxl.styles.PatternFill(start_color=fillColor, end_color=fillColor, fill_type='solid')

            #Set wraptext for potential long cells and multiline cells
            for i in range(1,41):#Old 26,41
                sheet.cell(row=curRow,column=i).alignment = openpyxl.styles.Alignment(vertical='top', wrapText=True)
            
            #Add cell borders:
            for i in range(1,41):
                sheet.cell(row=curRow,column=i).border = openpyxl.styles.borders.Border(left = openpyxl.styles.borders.Side(style = 'hair'),
                                                                                        right = openpyxl.styles.borders.Side(style = 'hair'),
                                                                                        top = openpyxl.styles.borders.Side(style = 'thin'),
                                                                                        bottom = openpyxl.styles.borders.Side(style = 'thin')
                                                                                        )
        if (curRow - 1) % 100 == 0:
            print(f"Processed {curRow - 1} entries", end='\r', flush=True)
        curRow += 1
    print(f"Processed {curRow-2} entries")
    # Auto-fit columns to fit the data
    for column in sheet.columns:
        max_length = 0
        column_letter = column[0].column_letter
        cellsWithData=0
        for cell in column:
            try:
                #wrapped_text = textwrap.wrap(str(cell.value), width=60)  # Adjust the width as needed
                wrapped_text = str(cell.value).strip()
                if cell.value and len(cell.value) > 0 and cell.value != 'N/A':
                    cellsWithData += 1
                for line in wrapped_text.splitlines():
                    if len(line) > max_length:
                        max_length = len(line)
                    
            except Exception as e:
                print(e)
                pass
        if hideEmptyColumns == False or cellsWithData > 1:
            adjusted_width = (max_length + 2) * 1.01  # Adjust the multiplier as needed
            if adjusted_width > maxWidth: #maxWidth set near the top of the script.
                adjusted_width = maxWidth
            sheet.column_dimensions[column_letter].width = adjusted_width
        else: 
            #All cells in the column are empty. Hide the column.
            sheet.column_dimensions[column_letter].hidden = True
            
    #Freeze the header row
    sheet.freeze_panes = sheet['A2']

    #Save the worksheet
    retry=True
    while (retry == True):
        try:
            outFile = file.replace(".csv",".xlsx")
            print("Saving to " + output_path + outFile)
            wb.save(output_path + outFile)
            print("Saved successfully!")
            retry = False
        except Exception as e:
            print(f'\nError writing to {output_path + outFile}\n    {e}')
            print("Please make sure the document is not currently open!")
            print("Press enter to retry. Press any other key to abort")
            strInput = input()
            if len(strInput) > 0:
                retry = False
        except:
            print("Write failed")
            retry = False
    

if not os.path.exists(input_path):
    print("input subfolder not found. It will be created for you.")
    os.makedirs(input_path)

if not os.path.exists(output_path):
    os.makedirs(output_path)

for path, dir, files in os.walk(input_path):
    if len(files) == 0:
        print("Please place DefenseProForensicReport.csv files in the .\input\ folder and rerun the script.")
    for file in files:
        if file.endswith(".tgz") or file.endswith(".zip"):
            try:
                print("zip/tgz file support to be added later: " + file)
            except Exception as err:
                print(f'Error processing {input_path + file} {err}')
        elif file.endswith(".csv"):
            print("Processing" + input_path + file)
            with open(input_path + file, 'r') as f:
                rawData = f.read()
                outFile = file.replace(".csv",".xlsx")
                if replaceExistingFile or not os.path.exists(output_path + outFile):
                    processData(rawData)
                else:
                    print(f"Output file: {output_path + outFile} already exists. Skipping the processing of {input_path + file}")    