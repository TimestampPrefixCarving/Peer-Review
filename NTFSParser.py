#NOTE: This code is a modified version from Nordvik et al. https://github.com/reviewscientific2020/cPTS.git

#Nordvik, R., Porter, K., Toolan, F., Axelsson, S. and Franke, K., 2020. Generic Metadata Time Carving. Forensic Science International: Digital Investigation, 33, p.301005.




import sys
import time
import sys
import datetime
import argparse
import math
import datetime
import csv
import codecs

#To do: add attribute lists.  Basically, what if the necessary attributes have been moved elsewhere. 

#This doesn't use mmap.  

global currentSIA 
	
global currentFNA

global SIALoc

global lastTSPos

global recordTS_Skip


#From stackoverflow
def read_in_chunks(file_object, chunk_size):
	"""Lazy function (generator) to read a file piece by piece.
	Default chunk size: 1k."""
	
	while True:
		data = file_object.read(chunk_size)
		if not data:
			break
		yield data


def bytesToDec(byteInput):
	tsString = byteInput[::-1].hex()
            
	decimalDate = int(tsString,16)

	return decimalDate


#Modified from https://forensicswiki.org/wiki/New_Technology_File_System_(NTFS)
def FromFiletime(filetime):

	if filetime < 0:
		return None
    

	if(filetime > 2147483647*10000000 + 116444736000000000):
		return "Invalid Timestamp"

	timestamp = filetime / 10

	dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)

	stringTime = dt.ctime()

	stringTime += (" Microseconds " + str(dt.microsecond) + " (UTC)")
 
	return stringTime


#Repetative, but I want to ensure it works.
#Modified from https://forensicswiki.org/wiki/New_Technology_File_System_(NTFS)
def FromFiletimeCSV(filetime):

	if filetime < 0:
		return None
    

	if(filetime > 2147483647*10000000 + 116444736000000000):
		return ["Invalid Timestamp", "Invalid Timestamp"]

	timestamp = filetime / 10

	dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=timestamp)

	stringTime = dt.strftime('%Y-%m-%d %H:%M:%S')

	microSeconds = dt.microsecond
 

	return [stringTime, microSeconds]




#must be greater than one byte
def byteArrayToInt(byteArray):

	littleEndian = byteArray[::-1].hex()
	finalInt = int(littleEndian, 16)

	return finalInt



#Read out next FNA
#Will need to return a number of variables...
def Next_FNA_Readout(f, data, relativeOffsetTS, offset, stringTime, page, pageSize):

	f.write("\nTimestamp: {}, FNA hit\n".format(stringTime))

	c_fnaLoc = offset + (page * pageSize)

	f.write("Byte Location (dec): {}\n".format(c_fnaLoc))

	f.write("Start of File Name Attribute (FNA)\n") 
		
	filenameLength = int(data[relativeOffsetTS + 56])	


	c_filename = data[(relativeOffsetTS + 58) : (relativeOffsetTS + 58 + 2*filenameLength)]


	filenameD = c_filename

	try:
		c_filename = filenameD.decode('utf-16')
	except:
		None


	f.write("Filename: {}\n".format(c_filename))


	#Print times...
	[c_fnaCre, created, c_fnaCreMS, c_fnaMod, modified, c_fnaModMS, c_fnaMFT, mftmodified, c_fnaMFTMS, c_fnaAcc, accessed, c_fnaAccMS] = printTimes(f, data, relativeOffsetTS)

	c_allocSize = byteArrayToInt(data[(relativeOffsetTS + 32) : (relativeOffsetTS + 40)])

	c_LogSize = byteArrayToInt(data[(relativeOffsetTS + 40) : (relativeOffsetTS + 42)])

	f.write("Allocated Size of File (dec): {}\n".format(c_allocSize))
	f.write("Logical Size of File (dec): {}\n".format(c_LogSize))

	c_pID = (data[(relativeOffsetTS - 8) : (relativeOffsetTS)]).hex()
	sumHold = 0

	j=0
	#Converting parent ID to integer (6 bytes)
	while j < 12:	
			hexS = c_pID[j:j+2]

			if((len(hexS) > 0)):
				sumHold = sumHold + int(hexS, 16)*(256**(int(j/2)))
	
			j = j + 2
		
	c_pID = sumHold

	f.write("Parent_ID: {}\n".format(c_pID))

	f.write("End of File Name Attribute (FNA)\n\n") 


	return [c_filename, c_fnaLoc, c_allocSize, c_LogSize, c_pID, c_fnaCre, created, c_fnaCreMS, c_fnaMod, modified, c_fnaModMS, c_fnaMFT, mftmodified, c_fnaMFTMS, c_fnaAcc, accessed, c_fnaAccMS]


#simple function that prints the timestamps in a SIA or FNA attribute
#May need to print out a number of variables.

#This can be fna or sia timestamps, it doesn't matter
def printTimes(f,data,locationFirstTimestamp):
	created = bytesToDec(data[locationFirstTimestamp : locationFirstTimestamp + 8])
	stringCreated = FromFiletime(created)

	[c_siaCre, c_siaCreMS] = FromFiletimeCSV(created)

	modified = bytesToDec(data[locationFirstTimestamp + 8 : locationFirstTimestamp + 16])
	stringModified = FromFiletime(modified)

	[c_siaMod, c_siaModMS] = FromFiletimeCSV(modified)

	mftmodified = bytesToDec(data[locationFirstTimestamp + 16  : locationFirstTimestamp + 24])
	stringMftmodified = FromFiletime(mftmodified)


	[c_siaMFT, c_siaMFTMS] = FromFiletimeCSV(mftmodified)


	accessed = bytesToDec(data[locationFirstTimestamp + 24 : locationFirstTimestamp +32])
	stringAccessed = FromFiletime(accessed)

	[c_siaAcc, c_siaAccMS] = FromFiletimeCSV(accessed)

	f.write("Created: {}\n".format(stringCreated))
	f.write("Modified: {}\n".format(stringModified))
	f.write("MFT Modified: {}\n".format(stringMftmodified))
	f.write("Accessed: {}\n".format(stringAccessed))

	return [c_siaCre, created, c_siaCreMS, c_siaMod, modified, c_siaModMS, c_siaMFT, mftmodified, c_siaMFTMS, c_siaAcc, accessed, c_siaAccMS]

#Recovery only checks the first two timestamps as starting locations of the matches, this is because there are some offset overlaps between SIAs and FNAs when needing to check relatively far
#off ranges.
def NTFS_FILEENTRY_RECOVERY(f, data, relativeOffsetTS, offset, page, pageSize, c):
	

	#declaring all the csv variables early, so they will be within scope
	#c.writerow(["SIA Location", "SIA created", "SIA Modified", "SIA MFT Modified", "SIA Accessed", "FNA Location", "Filename", "FNA created", "FNA Modified", "FNA MFT Modified", "FNA Accessed", 
	#"Allocated Size of File", "Logical Size of File", "Parent_ID", "Extra FNA Locations", "Extra Filenames", "Extra FNAs created", "Extra FNAs Modified", "Extra FNAs MFT Modified", 
	#"Extra FNAs Accessed", "Extra Allocated Size of File", "Extra Logical Size of File", "Extra Parent_ID", "Resident File?", "Resident Filesize", "Resident File (ASCII)", 
	#"Unit Compression Size", "Allocated Size of Attribute Content", "Actual Size of Attribute Content", "Initialized Size of Attribute content", "Datarun"])


	c_fileType = -1

	c_siaLoc = -1
	c_siaCre = -1
	c_siaCreD = -1
	c_siaCreMS = -1
	c_siaMod = -1
	c_siaModD = -1
	c_siaModMS = -1
	c_siaMFT = -1
	c_siaMFTD = -1
	c_siaMFTMS = -1
	c_siaAcc = -1
	c_siaAccD = -1
	c_siaAccMS = -1
	c_filename = "-1"
	c_fnaLoc = -1
	c_fnaCre = -1
	c_fnaCreD = -1
	c_fnaCreMS = -1
	c_fnaMod = -1
	c_fnaModD = -1
	c_fnaModMS = -1
	c_fnaMFT = -1
	c_fnaMFTD = -1
	c_fnaMFTMS = -1
	c_fnaAcc = -1
	c_fnaAccD = -1
	c_fnaAccMS = -1
	c_allocSize = -1
	c_LogSize = -1
	c_pID = -1
	c_ExFilename = []
	c_ExFnaLoc = []
	c_ExFnaCre = []
	c_ExFnaCreMS = []
	c_ExFnaMod = []
	c_ExFnaModMS = []
	c_ExFnaMFT = []
	c_ExFnaMFTMS = []
	c_ExFnaAcc = []
	c_ExFnaAccMS = []
	c_ExAllocSize = []
	c_ExLogSize = []
	c_ExPID = []
	c_resFile = None
	c_resFileSize = -1
	c_resFileAscii = ""
	c_UnitCompSize = -1
	c_AllocSizeAttr = -1
	c_ActualSizeAttrContent = -1
	c_InitSizeAttrContent = -1
	c_Datarun = ""
	c_iaDatarun = ""
	c_usn = -1





	c_aType = []

	search = None
	attriTestSIA = None 
	attriTestSIAFNA = None
	attriTestFNA = None

	SIA = b'\x10\x00\x00\x00'
	FNA = b'0\x00\x00\x00'
	DA = b'\x80\x00\x00\x00'
	AL = b'\x20\x00\x00\x00'

	
	global SIALoc

	global recordTS_Skip

	filenameLength = 0

	pairSIAFNA = False

	global currentSIA 
	
	global currentFNA

	global lastTSPos


	#NTFS SPECIFIC
	attriTestSIA = data[(relativeOffsetTS - 24):(relativeOffsetTS - 20)]
	attriTestSIAFNA = data[(relativeOffsetTS - 32):(relativeOffsetTS - 28)]
	attriTestFNA = data[(relativeOffsetTS - 40):(relativeOffsetTS - 36)]

	decimalDate = bytesToDec(data[relativeOffsetTS: relativeOffsetTS + 8])
	
        #Limit possible timestamps between plausible ranges
	if((decimalDate < 116444772000000000)   or (decimalDate > 157469220000000000)):
		return None


	stringTime = FromFiletime(decimalDate)

	#If we identified it as a SIA or possible FNA or SIA
	if ((attriTestSIA == SIA) or (attriTestSIAFNA == SIA)):
		f.write("\nTimestamp: {}, SIA hit\n".format(stringTime))
		f.write("Byte Location (dec): {}\n".format(offset + (page * pageSize)))
		currentSIA = True
		currentFNA = False
		if(attriTestSIA == SIA):
			SIALoc = relativeOffsetTS - 24
			tempOffset = offset - 24
		else:
			SIALoc = relativeOffsetTS - 32
			tempOffset = offset - 32

	
		#previously it was at a relative position
		c_siaLoc = offset + (page * pageSize)

		lastTSPos = offset + (page * pageSize)

		f.write("Start of Standard Information Attribute (SIA)\n") 
		#  Print SIA timestamps, assuming second timestamp
		firstTimestampPos = SIALoc + 24

		[c_siaCre, c_siaCreD,c_siaCreMS, c_siaMod, c_siaModD, c_siaModMS, c_siaMFT, c_siaMFTD, c_siaMFTMS, c_siaAcc, c_siaAccD, c_siaAccMS] = printTimes(f, data, firstTimestampPos)
		#  End printing SIA timestamps



		#Not unique enough
		c_usn = bytesToDec(data[(firstTimestampPos + 64):(firstTimestampPos + 72)])
		
		f.write("\nSIA Update Sequence Number: {}\n".format(c_usn))


		f.write("End of Standard Information Attribute (SIA)\n") 



		#Setting up to find data attribute
		headerTest = b'\x00\x00\x00\x00'
		currentHeaderLoc = SIALoc
		safetyCounter  = 0
		FNAcount = 0

		filetypeStr = ""


		#SIALoc might be the same as safetyCounter.  Update later.
		#While the header is not a data attribute, and we have not parsed some impossible length
		while( (headerTest != DA) and (currentHeaderLoc < (SIALoc + 968)) and (headerTest[0] < 128) and (safetyCounter < 1024)):
			
			headLength = byteArrayToInt(data[currentHeaderLoc + 4 : currentHeaderLoc + 8])
			
			#This is the length of the attribute.
			currentHeaderLoc += headLength

			tempOffset += headLength
			headerTest = data[(currentHeaderLoc) : (currentHeaderLoc + 4)]




			if(headerTest == AL):


				f.write("\nAttribute List:\n\n")


				attrListIterate = currentHeaderLoc + 24
				#This should be the length of a specific entry.
				aLength = byteArrayToInt(data[attrListIterate + 4: attrListIterate + 6])
				stuckloop = 0


				while(  (attrListIterate <  currentHeaderLoc + byteArrayToInt(data[currentHeaderLoc + 4 : currentHeaderLoc + 8]))  and (aLength != 0)):

					aType = byteArrayToInt(data[attrListIterate : attrListIterate + 4])
					aLength = byteArrayToInt(data[attrListIterate + 4: attrListIterate + 6])
					aNameLength =  data[attrListIterate + 6]
					aOffsetToName = data[attrListIterate + 7]
					aStartingVCN = byteArrayToInt(data[attrListIterate + 8: attrListIterate + 16])
					
					#This is the most important number.  Essentially gives us inode number.   First four bytes are to reference number.
					aRefAttr = byteArrayToInt(data[attrListIterate + 16: attrListIterate + 20])
					

					aID = byteArrayToInt(data[attrListIterate + 24: attrListIterate + 26])

					aName = ""

					if(aNameLength > 2):

						aName = data[attrListIterate + 26: attrListIterate + 2*aNameLength]

					attrListIterate += aLength

					stuckloop += 1

					

					f.write("Type: {}\n".format(aType))
					f.write("Length of Entry: {}\n".format(aLength))
					f.write("Length of Name: {}\n".format(aNameLength))
					f.write("Offset to Name: {}\n".format(aOffsetToName))
					f.write("Startubg VCN: {}\n".format(aStartingVCN))
					f.write("Reference Number to Attribute: {}\n".format(aRefAttr))
					f.write("ID: {}\n".format(aID))
					f.write("Name: {}\n\n".format(aName))

					c_aType.append(aType)
					c_aType.append(aRefAttr)




			#If it is an FNA
			if(headerTest == FNA):


				if(c_fileType == -1):
					c_fileType = int(data[currentHeaderLoc + 83])

					if(c_fileType == 0):
						filetypeStr = "File"
					elif(c_fileType == 16):
						filetypeStr = "Dir"
					elif(c_fileType == 32):
						filetypeStr = "Index View"
					elif(c_fileType == 48):
						filetypeStr = "Dir + Index View"



				decimalDate = bytesToDec(data[currentHeaderLoc + 32: currentHeaderLoc + 32 + 8])
				stringTime = FromFiletime(decimalDate)




				#We may need to print out more FNAs
				if(FNAcount == 0):
					[c_filename, c_fnaLoc, c_allocSize, c_LogSize, c_pID, c_fnaCre,c_fnaCreD, c_fnaCreMS, c_fnaMod, c_fnaModD, c_fnaModMS, c_fnaMFT, c_fnaMFTD, c_fnaMFTMS, c_fnaAcc, c_fnaAccD, c_fnaAccMS] = Next_FNA_Readout(f, data, (currentHeaderLoc + 32), (tempOffset + 32), stringTime, page, pageSize)
				else:
					[c_filenameX, c_fnaLocX, c_allocSizeX, c_LogSizeX, c_pIDX, c_fnaCreX, c_fnaCreXD, c_fnaCreMSX, c_fnaModX, c_fnaModXD, c_fnaModMSX, c_fnaMFTX, c_fnaMFTXD, c_fnaMFTMSX, c_fnaAccX, c_fnaAccXD, c_fnaAccMSX] = Next_FNA_Readout(f, data, (currentHeaderLoc + 32), (tempOffset + 32), stringTime, page, pageSize)

					c_ExFilename.append(c_filenameX)
					c_ExFnaLoc.append(c_fnaLocX)
					c_ExFnaCre.append(c_fnaCreX)
					c_ExFnaCreMS.append(c_fnaCreMSX)
					c_ExFnaMod.append(c_fnaModX)
					c_ExFnaModMS.append(c_fnaModMSX)
					c_ExFnaMFT.append(c_fnaMFTX)
					c_ExFnaMFTMS.append(c_fnaMFTMSX)
					c_ExFnaAcc.append(c_fnaAccX)
					c_ExFnaAccMS.append(c_fnaAccMSX)
					c_ExAllocSize.append(c_allocSizeX)
					c_ExLogSize.append(c_LogSizeX)
					c_ExPID.append(c_pIDX)



				#Add TS locations to skip
				recordTS_Skip.append(tempOffset + 32 + (page*pageSize))
				FNAcount += 1

			safetyCounter += 1

		if((headerTest == DA) and (FNAcount > 0)):

			f.write("Start of Data Attribute \n")

			#If 0, then print out resident information.
			if(data[currentHeaderLoc + 8] == 0):

				resFileSize = data[currentHeaderLoc + 16 : currentHeaderLoc + 20]

				c_resFile = "yes"


				resAscii = ""

				#Skip "RCRD" for $LogFile record header.
				if(resFileSize != b'\x52\x43\x52\x44'):

					correctWay = resFileSize[::-1].hex()
					rFS = int(correctWay,16)

					f.write("Resident Filesize: {}\n".format(rFS))

					c_resFileSize = rFS

					resFileOffset = data[currentHeaderLoc + 20 : currentHeaderLoc + 22]
					correctWay = resFileOffset[::-1].hex()
					rFO = int(correctWay,16)
					f.write("Resident File: ")
							
					hold = ""


					#maybe a different approach?
					#For resident file print out as much ascii as we can.
					for r in range(rFS):
						if(data[(currentHeaderLoc + rFO + r)] < 128):
							hold = str(chr(data[(currentHeaderLoc + rFO + r)]))
							f.write(hold)
							resAscii += hold

						else:
							hold = hex(data[(currentHeaderLoc + rFO + r)])
							f.write("\\{}".format(hold))
							resAscii += "\\"
							resAscii += hold

					c_resFileAscii = str(resAscii)
					c_resFileAscii = resAscii.encode("ascii")
					

					f.write("\n\n")

				else:
					f.write("Non-standard RCRD Data. Skipping typical output.\n\n")

					c_resFileAscii = "Non-standard RCRD Data. Skipping typical output."

			#If it is not resident...
			else:

				c_resFile = "no"

				c_UnitCompSize = byteArrayToInt(data[currentHeaderLoc + 34: currentHeaderLoc + 36])
				c_AllocSizeAttr  = byteArrayToInt(data[currentHeaderLoc + 40:currentHeaderLoc + 48])
				c_ActualSizeAttrContent   = byteArrayToInt(data[currentHeaderLoc + 48:currentHeaderLoc + 56])
				c_InitSizeAttrContent  = byteArrayToInt(data[currentHeaderLoc + 56 :currentHeaderLoc + 64])

				f.write("Unit compression size: {}\n".format(c_UnitCompSize))

				f.write("Allocated size of attribute content: {}\n".format(c_AllocSizeAttr ))

				f.write("Actual size of attribute content: {}\n".format(c_ActualSizeAttrContent ))

				f.write("Initialized size of attribute content: {}\n".format(c_InitSizeAttrContent ))

				dataRunLoc = data[currentHeaderLoc + 32]

				#DataRun Logic.
				nibbles = data[currentHeaderLoc + dataRunLoc]
				relativeDataAttr = dataRunLoc

				#Iterate over runs
				while ((nibbles != 0) and relativeDataAttr < 1024):
					relativeDataAttr += ((nibbles >> 4) + (nibbles & 15) + 1)
					nibbles = data[currentHeaderLoc + relativeDataAttr]

				c_Datarun = data[(currentHeaderLoc + dataRunLoc) : (currentHeaderLoc + relativeDataAttr )].hex()

				f.write("DataRun: {}\n\n".format(c_Datarun))

			if(data[currentHeaderLoc + 8] == 0):
				f.write("\nFile content is fully recoverable if resident file size is larger than 0\n")
			else:
				f.write("\nFile content is potentially recoverable (non-resident content)\n")
			currentSIA = False
			currentFNA = False
			relativeOffsetTS = SIALoc + 968

			f.write("End of Data Attribute \n")
	
			#This signifies we found some SIA+FNA+DA combination
			f.write("************************************************************\n")
			

			#Double check cPID type???
			if(c_fileType == 0):

				c.writerow([c_siaLoc, c_filename, c_pID, c_usn, filetypeStr, str(c_iaDatarun), c_ExFilename, c_siaCre, c_siaCreD, c_siaCreMS, c_siaMod, c_siaModD, c_siaModMS, c_siaMFT, c_siaMFTD, c_siaMFTMS, c_siaAcc, c_siaAccD, c_siaAccMS, c_fnaLoc, c_fnaCre, c_fnaCreD, c_fnaCreMS, c_fnaMod, c_fnaModD, c_fnaModMS, c_fnaMFT, c_fnaMFTD, c_fnaMFTMS, c_fnaAcc, c_fnaAccD, c_fnaAccMS, c_allocSize, c_LogSize, c_ExFnaLoc, c_ExFnaCre, c_ExFnaCreMS, c_ExFnaMod, c_ExFnaModMS, c_ExFnaMFT, c_ExFnaMFTMS, c_ExFnaAcc, c_ExFnaAccMS, c_ExAllocSize, c_ExLogSize, c_ExPID, c_resFile, c_resFileSize, c_resFileAscii, c_UnitCompSize, c_AllocSizeAttr, c_ActualSizeAttrContent, c_InitSizeAttrContent, c_aType, c_Datarun])

			#Add information to csv file.
			#c.writerow(["SIA Location", "SIA created", "SIA Modified", "SIA MFT Modified", "SIA Accessed","SIA Location", "Filename", "FNA created", "FNA Modified", "FNA MFT Modified", "FNA Accessed", "Allocated Size of File", "Logical Size of File", "Parent_ID", "Extra Filenames", "Extra FNAs created", "Extra FNAs Modified", "Extra FNAs MFT Modified", "Extra FNAs Accessed", "Extra Allocated Size of File", "Extra Logical Size of File", "Extra Parent_ID", "Resident File?", "Resident Filesize", "Resident File (ASCII)", "Unit Compression Size", "Allocated Size of Attribute Content", "Actual Size of Attribute Content", "Initialized Size of Attribute content", "Datarun"])

		
		#based on filetype 
		if(c_fileType == 16 or c_fileType == 32  or c_fileType == 48):
			
			IA = b'\xA0\x00\x00\x00'

	

			#need to loop through some more...
			while((currentHeaderLoc < (SIALoc + 968) - safetyCounter) and (headerTest[0] <= 160) and (safetyCounter < 1024)):
				
				headLength = byteArrayToInt(data[currentHeaderLoc + 4 : currentHeaderLoc + 8])
				#tempOffset += headLength
				
				#If it is an FNA
				if(headerTest == IA):

					#currently never get here????

					iaDatarunOffset = byteArrayToInt(data[currentHeaderLoc + 32 : currentHeaderLoc + 34])

					iaDRLoc = currentHeaderLoc + iaDatarunOffset

					#DataRun Logic.  Can be put into a function of its own
					nibbles = data[iaDRLoc]
					relativeDataAttr = 0

					#Iterate over runs
					while ((nibbles != 0) and relativeDataAttr < 1024):
						relativeDataAttr += ((nibbles >> 4) + (nibbles & 15) + 1)
						nibbles = data[iaDRLoc + relativeDataAttr]

					c_iaDatarun = data[(iaDRLoc) : (iaDRLoc + relativeDataAttr )].hex()



				currentHeaderLoc += headLength
				headerTest = data[(currentHeaderLoc) : (currentHeaderLoc + 4)]
				safetyCounter += 1

			#print(c_iaDatarun)
	
			c_iaDatarun = "\"" + c_iaDatarun
			c_iaDatarun = c_iaDatarun + "\""

			c_Datarun = "\"" + c_Datarun
			c_Datarun = c_Datarun + "\""

			#c.writerow([c_siaLoc, c_filename, c_pID, c_usn, filetypeStr, str(c_iaDatarun), c_ExFilename, c_siaCre, c_siaCreD, c_siaCreMS, c_siaMod, c_siaModD, c_siaModMS, c_siaMFT, c_siaMFTD, c_siaMFTMS, c_siaAcc, c_siaAccD, c_siaAccMS, c_fnaLoc, c_fnaCre, c_fnaCreD, c_fnaCreMS, c_fnaMod, c_fnaModD, c_fnaModMS, c_fnaMFT, c_fnaMFTD, c_fnaMFTMS, c_fnaAcc, c_fnaAccD, c_fnaAccMS, c_allocSize, c_LogSize, c_ExFnaLoc, c_ExFnaCre, c_ExFnaCreMS, c_ExFnaMod, c_ExFnaModMS, c_ExFnaMFT, c_ExFnaMFTMS, c_ExFnaAcc, c_ExFnaAccMS, c_ExAllocSize, c_ExLogSize, c_ExPID, c_resFile, c_resFileSize, c_resFileAscii, c_UnitCompSize, c_AllocSizeAttr, c_ActualSizeAttrContent, c_InitSizeAttrContent, c_aType, c_Datarun])
			c.writerow([c_siaLoc, c_filename, c_pID, c_usn, filetypeStr, str(c_iaDatarun), c_ExFilename, c_siaCre, c_siaCreD, c_siaCreMS, c_siaMod, c_siaModD, c_siaModMS, c_siaMFT, c_siaMFTD, c_siaMFTMS, c_siaAcc, c_siaAccD, c_siaAccMS, c_fnaLoc, c_fnaCre, c_fnaCreD, c_fnaCreMS, c_fnaMod, c_fnaModD, c_fnaModMS, c_fnaMFT, c_fnaMFTD, c_fnaMFTMS, c_fnaAcc, c_fnaAccD, c_fnaAccMS, c_allocSize, c_LogSize, c_ExFnaLoc, c_ExFnaCre, c_ExFnaCreMS, c_ExFnaMod, c_ExFnaModMS, c_ExFnaMFT, c_ExFnaMFTMS, c_ExFnaAcc, c_ExFnaAccMS, c_ExAllocSize, c_ExLogSize, c_ExPID, c_resFile, c_resFileSize, c_resFileAscii, c_UnitCompSize, c_AllocSizeAttr, c_ActualSizeAttrContent, c_InitSizeAttrContent, c_aType, c_Datarun])
			
			return 0


	#This can only happen if we don't have a SIA hit, and we straight output FNA information.
	#If it is identified as an FNA or possible SIA/FNA
	elif ((attriTestFNA == FNA) or (attriTestSIAFNA == FNA)):


		f.write("\nTimestamp: {}, FNA hit\n".format(stringTime))
		f.write("Byte Location (dec): {}\n".format(offset + (page * pageSize)))


		#From second timestamp ????  Regular FNA I am sure.
		if(attriTestFNA == FNA):
			f.write("Start of File Name Attribute (FNA)\n")
			filenameLength = int(data[relativeOffsetTS + 48])

			holdBytes = data[(relativeOffsetTS + 50) : (relativeOffsetTS + 50 + 2*filenameLength)]

			#print(holdBytes)

			testBytes = holdBytes


			try:
				holdBytes = testBytes.decode('utf-16')
			except:
				None

			f.write("Filename: {}\n".format(holdBytes))

			# Print FNA timestamps, assuming second timestamp
			firstTimestampPos = relativeOffsetTS - 8
			printTimes(f, data, firstTimestampPos)
			# End printing FNA timestamps

			alloSizeFile = byteArrayToInt(data[(relativeOffsetTS + 24) : (relativeOffsetTS + 32)])

			logicSizeFile = byteArrayToInt(data[(relativeOffsetTS + 32) : (relativeOffsetTS + 34)])

			f.write("Allocated Size of File (dec): {}\n".format(alloSizeFile))

			f.write("Logical Size of File (dec): {}\n".format(logicSizeFile))

			f.write("Parent_ID: {}\n".format((data[(relativeOffsetTS - 16) : (relativeOffsetTS - 8)]).hex()))
			f.write("End of File Name Attribute (FNA)\n\n")


		#from first timestamp
		else:
			f.write("Start of File Name Attribute (FNA)\n")
			filenameLength = int(data[relativeOffsetTS + 56])

			holdBytes = data[(relativeOffsetTS + 50) : (relativeOffsetTS + 50 + 2*filenameLength)]


			try:
				holdBytes = testBytes.decode('utf-16')
			except:
				None
				
			f.write("Filename: {}\n".format(holdBytes))
			
			# Print FNA timestamps, assuming first timestamp
			firstTimestampPos = relativeOffsetTS
			printTimes(f, data, firstTimestampPos)
			# End printing FNA timestamps

			alloSizeFile = byteArrayToInt(data[(relativeOffsetTS + 32) : (relativeOffsetTS + 40)])

			logicSizeFile = byteArrayToInt(data[(relativeOffsetTS + 40) : (relativeOffsetTS + 42)])

			f.write("Allocated Size of File (dec): {}\n".format(alloSizeFile))

			f.write("Logical Size of File (dec): {}\n".format(logicSizeFile))

			f.write("Parent_ID: {}\n".format((data[(relativeOffsetTS - 8) : (relativeOffsetTS)]).hex()))
			f.write("End of File Name Attribute (FNA)\n\n")

		currentFNA = True






#Need to reconstruct this but using memory mapping.  This mostly handles the reading in of large files in smaller memory pages.
def main(timestamps, fileLoc):    


	#I need to add an "extension" row.


	c = csv.writer(open("NTFSResults.csv", 'w', encoding='UTF16' ,newline=''))

	#May need to be editted.
	c.writerow(["SIA Location", "Filename",  "Parent_ID", "SIA Update Sequence Number", "File Type", "Index Attribute Datarun", "Extra Filenames", "SIA created", "SIA Created (Decimal)", "SIA Created ms", "SIA Modified", "SIA Modified (Decimal)", "SIA Modified ms", "SIA MFT Modified", "SIA MFT Modified (Decimal)", "SIA MFT Modified ms", "SIA Accessed","SIA Accessed (Decimal)","SIA Accessed ms", "FNA Location",  "FNA Created", "FNA Created (Decimal)","FNA created ms", "FNA Modified", "FNA Modified (Decimal)","FNA Modified ms", "FNA MFT Modified", "FNA MFT Modified (Decimal)","FNA MFT Modified ms", "FNA Accessed", "FNA Accessed (Decimal)" ,"FNA Accessed ms", "Allocated Size of File", "Logical Size of File", "Extra FNA Location", "Extra FNAs created", "Extra FNAs created ms", "Extra FNAs Modified", "Extra FNAs Modified ms", "Extra FNAs MFT Modified", "Extra FNAs MFT Modified ms", "Extra FNAs Accessed", "Extra FNAs Accessed ms", "Extra Allocated Size of File", "Extra Logical Size of File", "Extra Parent_ID", "Resident File?", "Resident Filesize", "Resident File (ASCII)", "Unit Compression Size", "Allocated Size of Attribute Content", "Actual Size of Attribute Content", "Initialized Size of Attribute content", "Basic Attribute List Information", "Datarun"])



	#This is the page size
	chunk_size = 8388608

	#Set possible prepend size
	prepend = 0

	#Read in list of timestamps, turn it into a list of ints
	timeList = [int(line.rstrip('\n')) for line in open(timestamps)]

	#Keeps track of byte location
	byteLocation = 0

	#Setting up var for later use
	totalLocation = 0

	#initialized here for C++ memory issues
	matchCount = 0

	#This is the threshold Iterator
	i = 0

	#Keeps track of chunk/page count
	currentPageNumber= 0

	#Did we add the end of the page to the next page?
	prependAHEAD = False

	#Did we add the end of the page from the previous page?
	prependLAST = False

	#Need to keep track of timestamps to skip
	global recordTS_Skip
	recordTS_Skip = []

	#Need to keep track if we are "in range" of a SIA
	global currentSIA 
	currentSIA = False
	
	#Need to keep track if we are "in range" of a FNA
	global currentFNA
	currentFNA = False

	#Need to keep track of where the SIA is (if it is too far from an FNA, we probably aren't reading an attribute)
	global SIALoc
	SIALoc = 0

	#Keep track of the last timestamp position.
	global lastTSPos
	lastTSPos = 0

	#File we write to and read from.
	f = codecs.open("NTFSResults.txt", "w", encoding = "utf-16")
	g = open(fileLoc, "rb")

	#Read a page for the start.
	page = g.read(chunk_size)

	#Set a temporary size, it may change depending on if we have prepended.
	tempChunkSize = chunk_size

	#Following is just to calculate progress...
	timestampCount = len(timeList)
	ten = True
	twen = True
	thir = True
	fort = True
	fift = True
	sixt = True
	seve = True
	eigh = True
	nint = True
	fini = True

	#Set variable if we need to skip the timestamp since we have already read it from some FNA
	skipStamp = False

	for i in range(len(timeList)):
		


		skipStamp = False

		#checks for repeating timestamps
		for ii in range(len(recordTS_Skip)):
			if(abs(timeList[i] - recordTS_Skip[ii] <= 16)):

				skipStamp = True
				del recordTS_Skip[ii]
				break

		#If we haven't been instructed to skip, we do it normally.
		if(skipStamp == False):
			
			#Get's the TS Location
			TSLoc = timeList[i]

			#Calculates TRUE page number
			timePageNumber = math.floor(TSLoc / chunk_size)
			
			#Calculates Offest (may change with prepending)
			pageOffset = TSLoc % chunk_size

			#Keep True offset
			realOffset = pageOffset

			#For giving progress reports
			timePercentage = i/timestampCount
			if(timePercentage > 0.1 and timePercentage < .2 and ten):
				print("Ten Percent Done\n")
				ten = False
			elif(timePercentage > 0.2 and timePercentage < .3 and twen):
				print("Twenty Percent Done\n")
				twen = False
			elif(timePercentage > 0.3 and timePercentage < .4 and thir):
				print("Thirty Percent Done\n")
				thir = False
			elif(timePercentage > 0.4 and timePercentage < .5 and fort):
				print("Forty Percent Done\n")
				fort = False
			elif(timePercentage > 0.5 and timePercentage < .6 and fift):
				print("Fifty Percent Done\n")
				fift = False
			elif(timePercentage > 0.6 and timePercentage < .7 and sixt):
				print("Sixty Percent Done\n")
				sixt = False
			elif(timePercentage > 0.7 and timePercentage < .8 and seve):
				print("Seventy Percent Done\n")
				seve = False
			elif(timePercentage > 0.8 and timePercentage < .9 and eigh):
				print("Eighty Percent Done\n")
				eigh = False
			elif(timePercentage > 0.9 and timePercentage < 1 and nint):
				print("Ninety Percent Done\n")
				nint = False


			if(timePageNumber - currentPageNumber > 1):
				if(prependAHEAD):
					currentPageNumber += 1
				prependAHEAD = False
				prependBehind = False


			#This is for looking in the center
			if((pageOffset > 1024) and (pageOffset < (chunk_size - 1024))):

				if(prependAHEAD and (timePageNumber - currentPageNumber == 1)):

					currentPageNumber += 1
					prependAHEAD = False

				else:
					if(prependAHEAD):
							currentPageNumber += 1
							prependAHEAD = False 
					for k in range(timePageNumber - currentPageNumber):
						page = g.read(chunk_size)
						currentPageNumber += 1
						prepend = 0
						prependAHEAD = False
						prependLAST = False
						tempChunkSize = chunk_size
						if not page:
							break

				prependAHEAD = False
				pageOffset += prepend

				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)



			#This is for timestamps at the beginning of the page
			elif((pageOffset >= 0) and (pageOffset <= 1024) and (currentPageNumber != 0) and (timePageNumber != currentPageNumber) and (prependAHEAD == False)):


				for k in range(timePageNumber - currentPageNumber - 1):
					page = g.read(chunk_size)
					currentPageNumber += 1
					tempChunkSize = chunk_size
					if not page:
						break

				page = page[-1024::]

				#Add new page.
				page += g.read(chunk_size)

				#You add plus one, since you already got the info from before.  TSpage should be same as CPage.
				currentPageNumber += 1


				#This should be our prepend value.
				prepend = 1024
				tempChunkSize = chunk_size + prepend

				#We took info from the previous page.
				prependLAST = True

				#must account for those 1024 bytes
				pageOffset += prepend

				
				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)



			#At start of page, but we have already prepended of the same type.  Furthermore, we are still on the same page.
			elif((pageOffset >= 0) and (pageOffset <= 1024) and (currentPageNumber != 0) and (timePageNumber == currentPageNumber) and (prependLAST)):
				pageOffset += prepend

				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)


			elif((pageOffset >= (chunk_size - 1024)) and (prependAHEAD == False)):

				for k in range(timePageNumber - currentPageNumber):
					page = g.read(chunk_size)
					currentPageNumber += 1
					tempChunkSize = chunk_size
					if not page:
						break


				#Gets you end of last chunk/page
				page = page[tempChunkSize - 1064: tempChunkSize]

				#Big difference here is that we have "not gone to the next page" 
				page += g.read(chunk_size)

				prepend = 1064

				#The last size, minus the offset, plus the prepend
				pageOffset = (prepend - (chunk_size - pageOffset)) 

				#This sets the forward chunk 
				tempChunkSize = chunk_size + prepend

				prependAHEAD = True
				prependLAST = False


				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)



			#only triggers when the difference between pages is 1.
			elif((pageOffset >= (chunk_size - 1024)) and (prependAHEAD == True) and (timePageNumber > currentPageNumber)):
				
				currentPageNumber += 1


				for k in range(timePageNumber - currentPageNumber):
					page = g.read(chunk_size)
					currentPageNumber += 1
					tempChunkSize = chunk_size
					if not page:
						break

				
				#Gets you end of last chunk/page
				page = page[tempChunkSize - 1064: tempChunkSize]

				#Big difference here is that we have "not gone to the next page" 
				page += g.read(chunk_size)

				prepend = 1064

				#The last size, minus the offset, plus the prepend
				pageOffset = (prepend - (chunk_size - pageOffset)) 

				#This sets the forward chunk 
				tempChunkSize = chunk_size + prepend

				prependAHEAD = True
				prependLAST = False


				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)



			#we have prepended from ahead		
			#We need a new page variable
			#This is using an old page
			#Basically, we are already looking at the "prepended" part
			elif( (pageOffset >= (chunk_size - 1024)) and (prependAHEAD == True) and (currentPageNumber == timePageNumber)):
				
				pageOffset = (prepend - (chunk_size - pageOffset))

				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)


			elif( ((pageOffset >= 0) and (pageOffset <= 1024) and (currentPageNumber != 0)  and (timePageNumber - currentPageNumber == 1) and (prependAHEAD == True))):
				

				#only difference is the non-change in page number.
				if(currentPageNumber < timePageNumber):
					currentPageNumber += 1

				pageOffset = (prepend + pageOffset)

				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)


				prependAHEAD = False

			elif( ((pageOffset >= 0) and (pageOffset <= 1024) and (currentPageNumber != 0)  and (timePageNumber ==  currentPageNumber) and (prependAHEAD == False))):
	

				pageOffset = (prepend + pageOffset)

				NTFS_FILEENTRY_RECOVERY(f, page, pageOffset, realOffset, timePageNumber, chunk_size, c)


	f.close()

	g.close()





if __name__ == '__main__':



	start = time.time()

	main(sys.argv[1],sys.argv[2])

	end = time.time()

	print(end - start)
