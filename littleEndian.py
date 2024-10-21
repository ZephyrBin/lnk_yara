def calc_little_endian_byte(hex_string):
    ordered_byte_string = ""
    for i in range(len(hex_string), 0, -2):
        ordered_byte_string+= hex_string[i-2:i]
    return ordered_byte_string


def calc_little_endian_bit(hex_string):
    ordered_bit_string= ""
    tmp= ""
    for i in range(0,len(hex_string), 2):
        tmp= "{0:08b}".format(int(hex_string[i:i+2], 16)) 
        ordered_bit_string+= tmp[::-1]
    return ordered_bit_string
