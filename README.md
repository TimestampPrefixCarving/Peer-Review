# Peer-Review
Tools for Timestamp Prefix Carving for Filesystem Metadata Extraction

# Purpose of this repository

The purpose of this repository is to provide access to the tools that we have written for our paper under peer-review, "Timestamp Prefix Carving for Filesystem Metadata Extraction", and to explain how to use them.  The provided files are modified versions from the Nordvik et al.'s paper and github.  

https://github.com/reviewscientific2020/cPTS.git

Nordvik, R., Porter, K., Toolan, F., Axelsson, S. and Franke, K., 2020. Generic Metadata Time Carving. Forensic Science International: Digital Investigation, 33, p.301005.


# Datasets

We have not provided the datasets used in our experiments, but the NTFS data can be found online.  

The dfr-13 NTFS image can be found here: https://www.cfreds.nist.gov/dfr-test-images.html

The LoneWolf NTFS image can be found here: https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario

The Ext4 image cannot be provided, as it contains personal data.

# How to compile the cPTS.cpp tool

Follow the instructions provided by Nordvik et al.

https://github.com/reviewscientific2020/cPTS/wiki/Compiling-the-C---tool

# How to use tools in general

To carve for filesystem metadata records, or tools need to be used in a specific sequence.  The first tool that should be used is the "potential timestamp Carver", cPTS.cpp.  This tool will return a text file named cPTS.txt, which holds a list of potential timestamp locations determined by a number of user set rules.  The entries of the list are written in a byte offsets from the beginning of the disk).  This file can become quite large.

From this point, you can either use the NTFS MFT record parser (NTFSparser.py) or the Ext4 inode parser (Ext4Parser.py).  These tools take in the cPTS.txt file as input, and will output a text file and csv file of record information.  The csv file is the primary output that shows specifically identified records (the text file is more of a log). 

# How to run the cPTS.cpp tool.

Once an executable cPTS.exe is compiled, the program takes the following mandatory arguments:

<disk image location> <timestamp size> <search threshold> <number of timestamps that should be the same>
  
Optional arguments include:

<min date> <max date> <-t> <-p>
  
-t is for limiting matches between NTFS dates and -p is for prefix-based timestamp matching.  Follow -p with the length of the most signficant number of bytes you wish to match for the timestamps.

For example, if we wanted to search for timestamps of length 8, where we had a search window in front of each timestamp of 24 bytes, required a minimum of 3 total matching timestamps (of 4), and were only considering the 3 most significant bytes of each timestamp:

cPTS.exe dfr-13-ntfs.dd 8 24 3 -p 3

# How to run the NTFSparser.py tool:

Assuming Python 3 is installed (and all required dependencies found within the file are installed) the program takes the following arguments:

<location of potential timestamp list> <disk image location>

For example, if we wanted to search for MFT records on an assumed NTFS image, we would run the following:

python NTFSParser.py cPTS.txt dfr-13-ntfs.dd

# How to rune the Ext4Parser.py tool:

Assuming Python 3 is installed (and all required dependencies found within the file are installed) the program takes the following mandatory arguments:

<location of potential timestamp list> <disk image location> <byte offset to beginning of target partition> <assumed size of Ext block in bytess>

Optional arguments include:

<-m>

This flag will attempt to hash the file contents of identified inodes.

For example, if we wanted to search for inodes on an assumed Ext4 image, we would run the following:

python ext4Parser.py cPTS.txt "C:\Disk Images\Samsung\SamsungS8.dd" 221872128 4096


Near line 1189 you may encounter a problem with memory mapping.  The uploaded file was tested on Windows, but is known to have issues on Mac.  If you encounter such issues, try replacing line 1189:

f = open(fileLoc, "rb+") -> f = open(fileLoc, "rb")

and line 1192:

mapF = mmap.mmap(f.fileno(), 0) -> mapF = mmap.mmap(f.fileno(), 0, prot=0x01)

The directions are also in the comments of the code.
