import glob
import datetime
import os
import shutil
from constant import TMP_DIR, TMP_DIR2


def find_lnkfiles(start_location):
    files = glob.glob(start_location + '/**/*.[lL][nN][kK]', recursive=True)
    return files

def open_lnkfiles(files_list):
    lnk_hex_list= []
    try:
        for i in files_list:
            with open(i, 'rb') as f:
                lnk_hex_list.append(f.read().hex())
    except: 
        lnk_hex_list.append("")
    return lnk_hex_list

def write_results(results, scan_type):
    current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{scan_type}_results_{current_time}.txt"

    with open(filename, "w") as f:
        if results:
            for result in results:
                f.write(result)
                f.write("\n")
        else:
            f.write("No results\n")

def copy_tmp(files):
    if (os.path.exists(TMP_DIR)):
        shutil.rmtree(TMP_DIR)
    os.mkdir(TMP_DIR)
    tmp_num= 0
    tmp_list= []
    for file in files:
        shutil.copy(f'{file}', f'{TMP_DIR}'+"\\"+f'{tmp_num}')
        tmp_list.append(f'{TMP_DIR}'+"\\"+f'{tmp_num}')
        tmp_num+= 1
    return tmp_list

def copy_tmp2(files):
    if (os.path.exists(TMP_DIR2)):
        shutil.rmtree(TMP_DIR2)
    os.mkdir(TMP_DIR2)
    tmp_num= 0
    tmp_list= []
    for file in files:
        shutil.copy(f'{file}', f'{TMP_DIR2}'+"\\"+f'{tmp_num}')
        tmp_list.append(f'{TMP_DIR2}'+"\\"+f'{tmp_num}')
        tmp_num+= 1
    return tmp_list