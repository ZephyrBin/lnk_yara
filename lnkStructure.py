from littleEndian import calc_little_endian_bit, calc_little_endian_byte

def hextoint(hex):
    return int(hex, 16)

def extract_extrablock_ID(lnk_hex_string):
    id_list = []
    
    current_position = 76 * 2
    
    flags = calc_little_endian_bit(lnk_hex_string[40:48])
    
    if flags[0] == "1":
        list_size = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+4]))
        current_position += 2 * 2 
        current_position += list_size * 2
    
    if flags[1] == "1":
        info_size = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+4]))
        current_position += info_size * 2
    
    for i in range(2, 7):
        if flags[i] == "1":
            count = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+4]))
            current_position += 2 * 2
            current_position += count * 2 * 2
    
    while current_position < len(lnk_hex_string) - 32:
        block_size = hextoint(calc_little_endian_byte(lnk_hex_string[current_position:current_position+8]))
        
        if block_size == 0:
            break
            
        signature = lnk_hex_string[current_position+8:current_position+16]
        
        id_list.append(signature)
        
        current_position += block_size * 2
        
        if block_size < 8:
            break
            
    return id_list