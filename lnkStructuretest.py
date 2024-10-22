from littleEndian import calc_little_endian_bit, calc_little_endian_byte

def hextoint(hex):
    return int(hex, 16)

def extract_extrablock_ID(lnk_hex_string):
    id_list = []
    
    # Header size is 0x4C (76) bytes
    current_position = 76 * 2  # Multiply by 2 because hex string has 2 chars per byte
    
    # Get LinkFlags from offset 0x14 (20)
    flags = calc_little_endian_bit(lnk_hex_string[40:48])
    
    # Skip LinkTargetIDList if present (flag bit 0)
    if flags[0] == "1":
        list_size = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+4]))
        current_position += 4 * 2  # Skip size field
        current_position += list_size * 2
    
    # Skip LinkInfo if present (flag bit 1)
    if flags[1] == "1":
        info_size = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+4]))
        current_position += info_size * 2
    
    # Skip StringData if present (flags bits 2-6)
    string_flags = flags[2:7]  # NAME_STRING, RELATIVE_PATH, WORKING_DIR, COMMAND_LINE_ARGUMENTS, ICON_LOCATION
    for i, flag in enumerate(string_flags):
        if flag == "1":
            # Get character count (including spaces and special chars)
            count = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+2]))
            current_position += 2 * 2  # Skip count field
            
            # Calculate total size: count * 2 (unicode) * 2 (hex chars per byte)
            string_size = count * 2 * 2
            
            # Debug print for COMMAND_LINE_ARGUMENTS (flag index 3)
            if i == 3:  # COMMAND_LINE_ARGUMENTS
                string_data = lnk_hex_string[current_position:current_position+string_size]
                print(f"Command line args size: {count}")
                print(f"Command line hex: {string_data}")
            
            current_position += string_size
    
    # Process ExtraData blocks
    while current_position < len(lnk_hex_string) - 16:
        # Get block size (4 bytes)
        block_size = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+8]))
        
        if block_size == 0:
            break
            
        # Get signature (4 bytes)
        signature = lnk_hex_string[current_position+8:current_position+16]
        
        # Add valid signature to list
        if signature != "00000000":
            id_list.append(signature)
            print(f"Found signature: {signature} at position: {current_position}")
        
        # Move to next block
        current_position += block_size * 2
        
        # Safety check
        if block_size < 8:  # Minimum block size is 8 bytes
            print(f"Warning: Invalid block size ({block_size}) detected")
            break
            
    return id_list