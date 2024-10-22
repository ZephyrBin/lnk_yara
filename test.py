from constant import DEFAULT_LOCATION,TMP_DIR,MALWARE_LOCATION
from windowsIO import find_lnkfiles, write_results, open_lnkfiles
from yaraModule import detect_YARA_quick, detect_YARA_full
from lnkStructure import extract_extrablock_ID

#lnk_files= find_lnkfiles(DEFAULT_LOCATION)
#detect_YARA_full(detect_YARA_quick(lnk_files))
lnk = open_lnkfiles(find_lnkfiles(MALWARE_LOCATION))
print(extract_extrablock_ID(lnk[0]))