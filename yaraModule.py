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

import yara
import os
import shutil
from typing import List, Dict, Union

def detect_YARA_full(files: List[str]) -> None:
    """
    Detect malicious Extra Block IDs in LNK files using YARA rules
    """
    # 결과 저장을 위한 딕셔너리들
    results: List[str] = []
    matching_file_dict: Dict[int, str] = {}
    matching_rule_dict: Dict[int, str] = {}
    matching_error_dict: Dict[int, str] = {}

    try:
        # YARA 규칙 컴파일
        rules = yara.compile(filepath=FULL_YARA_RULE_LOCATION)
        
        # 임시 파일 복사
        copied_files = copy_tmp2(files)
        
        # 파일 복사 완료 대기
        while not all(os.path.exists(file) for file in copied_files):
            continue
            
        # LNK 파일들의 hex 데이터 읽기
        hex_data_list = open_lnkfiles(copied_files)
        
        # 각 파일 처리
        for i, original_file in enumerate(files):
            print(f"Processing file {i}: {original_file}")
            
            matching_file_dict[i] = original_file
            
            try:
                # Extra Block ID 추출
                extra_block_ids = extract_extrablock_ID(hex_data_list[i])
                
                if not extra_block_ids:
                    matching_error_dict[i] = f"Error occurred while processing {original_file}"
                    continue
                    
                # Extra Block 개수 검증
                if len(extra_block_ids) > 12:
                    matching_error_dict[i] = f"File {original_file} exceeded extra data block limit (12)"
                    continue
                
                # 각 Extra Block ID에 대해 YARA 규칙 매칭
                for block_id in extra_block_ids:
                    # block_id를 바이너리 형태로 변환
                    block_data = bytes.fromhex(block_id)
                    
                    try:
                        matches = rules.match(data=block_data)
                        
                        if matches:
                            for match in matches:
                                rule_info = f"Rule '{match.rule}' matched"
                                
                                # 매칭된 문자열 정보 추가
                                string_details = [f"- Found: {s[2].hex()}" for s in match.strings]
                                
                                matching_rule_dict[i] = (
                                    f"File: {original_file}\n"
                                    f"{rule_info}\n"
                                    f"Block ID: {block_id}\n"
                                    f"{''.join(string_details)}"
                                )
                                
                    except yara.Error as e:
                        matching_error_dict[i] = f"YARA error for {original_file} - Block ID {block_id}: {str(e)}"
                        
            except Exception as e:
                matching_error_dict[i] = f"Processing error for {original_file}: {str(e)}"
                
        # 결과 수집
        for i in range(len(files)):
            if i in matching_rule_dict:
                results.append(matching_rule_dict[i])
            if i in matching_error_dict:
                results.append(matching_error_dict[i])
                
    except Exception as e:
        results.append(f"Global error: {str(e)}")
        
    finally:
        # 임시 파일 정리
        try:
            shutil.rmtree(TMP_DIR)
        except Exception as e:
            results.append(f"Cleanup error: {str(e)}")
        
        # 결과 저장
        write_results(results, "full")

def write_results(results: List[str], prefix: str) -> None:
    """결과를 파일에 저장"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{prefix}_results_{timestamp}.txt"
    
    with open(filename, "w", encoding="utf-8") as f:
        for result in results:
            f.write(f"{result}\n")