from constant import DEFAULT_LOCATION
from windowsIO import find_lnkfiles
from yaraModule import detect_YARA_quick

lnk_files= find_lnkfiles(DEFAULT_LOCATION)
detect_YARA_quick(lnk_files)