from littleEndian import calc_little_endian_bit, calc_little_endian_byte

def hextoint(hex):
    return int(hex, 16)

def extract_extrablock_ID(lnk_hex_string):
    id_list= []

    flags= calc_little_endian_bit(lnk_hex_string[40:49])

    current_number= 0
    header_size= hextoint("4C")

    current_number += header_size * 2

    if (flags[0] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+4]))* 2
        current_number+= 4
        current_number+= jump_value

    if (flags[1] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+8]))* 2
        current_number+= 8
        current_number+= jump_value

    if (flags[2] == "1"):
        print(current_number)
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+4]))* 2
        current_number+= 4
        current_number+= jump_value
        print(current_number)

    if (flags[3] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+4]))* 2
        current_number+= 4
        current_number+= jump_value

    if (flags[4] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+4]))* 2
        current_number+= 4
        current_number+= jump_value

    if (flags[5] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+4]))* 2
        current_number+= 4
        current_number+= jump_value
        print(jump_value)
        print(current_number)

    if (flags[6] == "1"):
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number:current_number+4]))* 2
        current_number+= 4
        current_number+= jump_value



    print (current_number)
    while(current_number< len(lnk_hex_string)-1):
        if ((lnk_hex_string[current_number+9:current_number+17]) == "00000000"):
            break
        id_list.append(lnk_hex_string[current_number+9:current_number+17])
        print(lnk_hex_string[current_number+9:current_number+17])
        jump_value= hextoint(calc_little_endian_byte(lnk_hex_string[current_number+1:current_number+9]))* 2
        current_number+= jump_value

    return id_list