import yara
from constant import QUICK_YARA_RULE_LOCATION, FULL_YARA_RULE_LOCATION, TMP_DIR, TMP_DIR2
from windowsIO import write_results, open_lnkfiles, copy_tmp, copy_tmp2
from lnkStructure import extract_extrablock_ID
import shutil
import os
from typing import List, Dict, Union

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
    print("Quick detection results: \n")
    for result in results:
        print(f"{result}")
    print("Analyze quick results save file for details")
    return detected_files

def detect_YARA_precise(files: List[str]) -> None:
    results: List[str] = []
    matching_file_dict: Dict[int, str] = {}
    matching_rule_dict: Dict[int, str] = {}
    matching_error_dict: Dict[int, str] = {}

    try:
        rules = yara.compile(filepath=FULL_YARA_RULE_LOCATION)
        
        copied_files = copy_tmp2(files)
        
        while not all(os.path.exists(file) for file in copied_files):
            continue
            
        hex_data_list = open_lnkfiles(copied_files)
        
        for i, original_file in enumerate(files):
            
            matching_file_dict[i] = original_file
            
            try:
                extra_block_ids = extract_extrablock_ID(hex_data_list[i])
                
                if not extra_block_ids:
                    matching_error_dict[i] = f"Error occurred while processing {original_file} \n"
                    continue
                    
                if len(extra_block_ids) > 12:
                    matching_error_dict[i] = f"File {original_file} exceeded extra data block limit (12) \n"
                    continue
                
                for block_id in extra_block_ids:
                    block_data = bytes.fromhex(block_id)
                    
                    try:
                        matches = rules.match(data=block_data)
                        
                        if matches:
                            for match in matches:
                                rule_info = f"Rule '{match.rule}' matched"
                                
                                string_details = [f"- Found: {s[2].hex()}" for s in match.strings]
                                
                                matching_rule_dict[i] = (
                                    f"File: {original_file}\n"
                                    f"{rule_info}\n"
                                    f"Block ID: {block_id}\n"
                                    f"{''.join(string_details)}"
                                )
                                
                    except yara.Error as e:
                        matching_error_dict[i] = f"YARA error for {original_file} - Block ID {block_id}: {str(e)} \n"
                        
            except Exception as e:
                matching_error_dict[i] = f"Processing error for {original_file}: {str(e)} \n"
                
        for i in range(len(files)):
            if i in matching_rule_dict:
                results.append(matching_rule_dict[i])
            if i in matching_error_dict:
                results.append(matching_error_dict[i])
                
    except Exception as e:
        results.append(f"Global error: {str(e)}")
        
    finally:
        try:
            shutil.rmtree(TMP_DIR2)
        except Exception as e:
            results.append(f"Cleanup error: {str(e)}")
        
        write_results(results, "precise")
        print("Precise detection results: \n")
        for result in results:
            print(f"{result}")
        print("Analyze quick results save file for details")
        return results
