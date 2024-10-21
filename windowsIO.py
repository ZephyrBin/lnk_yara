import glob
import datetime


def find_lnkfiles(start_location):
    files = glob.glob(start_location + '/**/*.[lL][nN][kK]', recursive=True)
    return files

def open_lnkfiles(files_list):
    lnk_hex_list= []
    for i in files_list:
        with open(i, 'rb') as f:
            lnk_hex_list.append(f.read().hex())
    return lnk_hex_list

def write_results(results, scan_type):
    current_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{scan_type}_results_{current_time}.txt" if results else f"no_results_{current_time}.txt"

    with open(filename, "w") as f:
        if results:
            for result in results:
                f.write(result)
                f.write("\n")
        else:
            f.write("No results\n")
