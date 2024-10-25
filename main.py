__author__ = "JowonReady"
__version__ = "1.70"
__last_modification__ = "2024-10-25"


import datetime
import pyfiglet
import argparse


from constant import DEFAULT_LOCATION
from windowsIO import find_lnkfiles
from yaraModule import detect_YARA_quick, detect_YARA_precise


def main():
    start_time = datetime.datetime.now()
    print()
    print('='*64)
    print()
    ascii_banner = pyfiglet.figlet_format("JowonReady")
    print(ascii_banner)
    print('='*64)
    print()
    print(f"YARA Detection System v{__version__}")
    print(f"Last Modification: {__last_modification__}")
    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    print()
    
    parser = argparse.ArgumentParser(description="YARA Detection System")
    parser.add_argument("target", metavar="target_location", nargs='?', default=DEFAULT_LOCATION, type=str,
                        help="Type Target Location. Default will be your home directory.")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick Scan")
    parser.add_argument("-p", "--precise", action="store_true", help="Precise Scan")
    args = parser.parse_args()
    
    # Find LNK Files Recursively
    target_location = args.target
    lnk_files= find_lnkfiles(target_location)

    if args.quick:
        detect_YARA_quick(lnk_files)

    if args.precise:
        detect_YARA_precise(detect_YARA_quick(lnk_files))

    end_time = datetime.datetime.now()
    duration = end_time - start_time
    print(f"Estimated time:\t{duration}")


if __name__ == "__main__":
    main()