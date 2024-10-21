from littleEndian import calc_little_endian_bit, calc_little_endian_byte

def hextoint(hex):
    return int(hex, 16)

def extract_extrablock_ID(lnk_hex_list):
    id_list= []

    lnk_hex_list[40:49]
    flags= calc_little_endian_bit(lnk_hex_list)

    current_number= 0
    header_size= hextoint("4C")

    current_number += header_size

    if (flags[0] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+5]))
        current_number+= 4
        current_number+= jump_value

    if (flags[1] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+9]))
        current_number+= 8
        current_number+= jump_value

    if (flags[2] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+5]))
        current_number+= 4
        current_number+= jump_value

    if (flags[3] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+5]))
        current_number+= 4
        current_number+= jump_value

    if (flags[4] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+5]))
        current_number+= 4
        current_number+= jump_value

    if (flags[5] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+5]))
        current_number+= 4
        current_number+= jump_value

    if (flags[6] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+5]))
        current_number+= 4
        current_number+= jump_value

    while(current_number< len(lnk_hex_list)-1):
        id_list.append(lnk_hex_list[current_number+9:current_number+17])
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_list[current_number+1:current_number+9]))
        current_number+= jump_value

    return id_list