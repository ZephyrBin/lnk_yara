import yara
from constant import QUICK_YARA_RULE_LOCATION, FULL_YARA_RULE_LOCATION, TMP_DIR
from windowsIO import write_results, open_lnkfiles, copy_tmp, copy_tmp2
from lnkStructure import extract_extrablock_ID
import shutil
import os


def detect_YARA_quick(files):
    rules = yara.compile(filepath=QUICK_YARA_RULE_LOCATION)
    results = []
    detected_files = []
    copied_files= copy_tmp(files)
    matching_file_dict= {}
    matching_rule_dict= {}
    matching_error_dict= {}
    for i in range(0, len(copied_files)):
        matching_file_dict[i]= files[i]
        try:
            matches= rules.match(copied_files[i])
            if matches:
                for match in matches:
                        matching_rule_dict[i]= f"{match.rule} + \n"
                        for s in match.strings:
                            matching_rule_dict[i]= f"{matching_rule_dict[i]}"+ f"   - {s}\n"
                detected_files.append(matching_file_dict[i])
        except yara.Error as e:  
            matching_error_dict[i]= {str(e)}
    for i in range(0, len(copied_files)):
        if(i in matching_rule_dict):
            results.append(f"file {matching_file_dict[i]} matches rule: '{matching_rule_dict[i]}' \n")
        if(i in matching_error_dict):
            results.append(f"{matching_error_dict[i]}")
    shutil.rmtree(TMP_DIR)
    write_results(results, "quick")
    return detected_files


def detect_YARA_full(files):
    rules = yara.compile(filepath=FULL_YARA_RULE_LOCATION)
    results = []
    copied_files= copy_tmp2(files)
    matching_file_dict= {}
    matching_rule_dict= {}
    matching_error_dict= {}
    waiting_file= 0
    while waiting_file== 0:
        waiting_file= 1
        for i in range(0, len(copied_files)):
            if (os.path.exists(copied_files[i])):
                waiting_file= waiting_file & 1
            else: waiting_file= waiting_file & 0
    hex_data_list= open_lnkfiles(copied_files)

    for i in range(0, len(copied_files)):
        print(f"processing {i}:\n")
        matching_file_dict[i]= files[i]
        hex_data= extract_extrablock_ID(hex_data_list[i])
        if(hex_data == ""):
           matching_error_dict[i]= f"error occurred while processing {matching_file_dict[i]}"
        else:
            file_ID_values = extract_extrablock_ID(hex_data)
            if (len(file_ID_values)>12):
                matching_error_dict[i]= f"file {matching_file_dict[i]} exceeded extra data block limit. \n"
            else:
                try:
                    for file_ID_value in file_ID_values:
                        matches= rules.match(file_ID_value)
                        if matches:
                            for match in matches:
                                matching_rule_dict[i]= f"file {matching_file_dict[i]} {match.rule}: + \n"
                                for s in match.strings:
                                    matching_rule_dict[i]= f"has undefined data block ID. \n"
                except yara.Error as e:  
                    matching_error_dict[i]= {str(e)}
    for i in range(0, len(copied_files)):
        if(i in matching_rule_dict):
            results.append(f"file {matching_file_dict[i]} matches rule: '{matching_rule_dict[i]}' \n")
        if(i in matching_error_dict):
            results.append(f"{matching_error_dict[i]}")
     

    shutil.rmtree(TMP_DIR)
    write_results(results, "full")