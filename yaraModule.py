import yara
from constant import QUICK_YARA_RULE_LOCATION, FULL_YARA_RULE_LOCATION
from windowsIO import write_results, open_lnkfiles
from lnkStructure import extract_extrablock_ID


def detect_YARA_quick(files):
    rules = yara.compile(filepath=QUICK_YARA_RULE_LOCATION)
    results = []
    detected_files = []

    for file in files:
        try:
            matches = rules.match(file)
            if matches:
                for match in matches:
                    result = f"file {file} matches rule '{match.rule}' with string:\n"
                    for s in match.strings:
                        result += f"   - {s}\n"
                    results.append(result)
                    detected_files.append(file)
        except yara.Error as e:  
            error_message = f"Error occurred while processing file {file}: {str(e)}"
            results.append(error_message)

    write_results(results, "quick")
    return detected_files

def detect_YARA_full(files):
    rules = yara.compile(filepath=FULL_YARA_RULE_LOCATION)
    results = []

    for file in files:
        file_ID_values = extract_extrablock_ID(open_lnkfiles(file))
        if (len(file_ID_values)>12):
            result= f"file {file} exceeded extra data block limit. \n"
        try:
            for file_ID_value in file_ID_values:
                matches = rules.match(file_ID_value)
                if matches:
                    for match in matches:
                        result = f"file {file} has undefined extra data block:\n"
                        for s in match.strings:
                            result += f"   - {s}\n"
                        results.append(result)
                    break
        except yara.Error as e:
            error_message = f"Error occurred while processing file {file}: {str(e)}"
            results.append(error_message)
    
    write_results(results, "full")