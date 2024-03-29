from src.cryptopals import xor

forward_s_box = [\
    [b"\x63", b"\x7c", b"\x77", b"\x7b", b"\xf2", b"\x6b", b"\x6f", b"\xc5", b"\x30", b"\x01", b"\x67", b"\x2b", b"\xfe", b"\xd7", b"\xab", b"\x76"],\
    [b"\xca", b"\x82", b"\xc9", b"\x7d", b"\xfa", b"\x59", b"\x47", b"\xf0", b"\xad", b"\xd4", b"\xa2", b"\xaf", b"\x9c", b"\xa4", b"\x72", b"\xc0"],\
    [b"\xb7", b"\xfd", b"\x93", b"\x26", b"\x36", b"\x3f", b"\xf7", b"\xcc", b"\x34", b"\xa5", b"\xe5", b"\xf1", b"\x71", b"\xd8", b"\x31", b"\x15"],\
    [b"\x04", b"\xc7", b"\x23", b"\xc3", b"\x18", b"\x96", b"\x05", b"\x9a", b"\x07", b"\x12", b"\x80", b"\xe2", b"\xeb", b"\x27", b"\xb2", b"\x75"],\
    [b"\x09", b"\x83", b"\x2c", b"\x1a", b"\x1b", b"\x6e", b"\x5a", b"\xa0", b"\x52", b"\x3b", b"\xd6", b"\xb3", b"\x29", b"\xe3", b"\x2f", b"\x84"],\
    [b"\x53", b"\xd1", b"\x00", b"\xed", b"\x20", b"\xfc", b"\xb1", b"\x5b", b"\x6a", b"\xcb", b"\xbe", b"\x39", b"\x4a", b"\x4c", b"\x58", b"\xcf"],\
    [b"\xd0", b"\xef", b"\xaa", b"\xfb", b"\x43", b"\x4d", b"\x33", b"\x85", b"\x45", b"\xf9", b"\x02", b"\x7f", b"\x50", b"\x3c", b"\x9f", b"\xa8"],\
    [b"\x51", b"\xa3", b"\x40", b"\x8f", b"\x92", b"\x9d", b"\x38", b"\xf5", b"\xbc", b"\xb6", b"\xda", b"\x21", b"\x10", b"\xff", b"\xf3", b"\xd2"],\
    [b"\xcd", b"\x0c", b"\x13", b"\xec", b"\x5f", b"\x97", b"\x44", b"\x17", b"\xc4", b"\xa7", b"\x7e", b"\x3d", b"\x64", b"\x5d", b"\x19", b"\x73"],\
    [b"\x60", b"\x81", b"\x4f", b"\xdc", b"\x22", b"\x2a", b"\x90", b"\x88", b"\x46", b"\xee", b"\xb8", b"\x14", b"\xde", b"\x5e", b"\x0b", b"\xdb"],\
    [b"\xe0", b"\x32", b"\x3a", b"\x0a", b"\x49", b"\x06", b"\x24", b"\x5c", b"\xc2", b"\xd3", b"\xac", b"\x62", b"\x91", b"\x95", b"\xe4", b"\x79"],\
    [b"\xe7", b"\xc8", b"\x37", b"\x6d", b"\x8d", b"\xd5", b"\x4e", b"\xa9", b"\x6c", b"\x56", b"\xf4", b"\xea", b"\x65", b"\x7a", b"\xae", b"\x08"],\
    [b"\xba", b"\x78", b"\x25", b"\x2e", b"\x1c", b"\xa6", b"\xb4", b"\xc6", b"\xe8", b"\xdd", b"\x74", b"\x1f", b"\x4b", b"\xbd", b"\x8b", b"\x8a"],\
    [b"\x70", b"\x3e", b"\xb5", b"\x66", b"\x48", b"\x03", b"\xf6", b"\x0e", b"\x61", b"\x35", b"\x57", b"\xb9", b"\x86", b"\xc1", b"\x1d", b"\x9e"],\
    [b"\xe1", b"\xf8", b"\x98", b"\x11", b"\x69", b"\xd9", b"\x8e", b"\x94", b"\x9b", b"\x1e", b"\x87", b"\xe9", b"\xce", b"\x55", b"\x28", b"\xdf"],\
    [b"\x8c", b"\xa1", b"\x89", b"\x0d", b"\xbf", b"\xe6", b"\x42", b"\x68", b"\x41", b"\x99", b"\x2d", b"\x0f", b"\xb0", b"\x54", b"\xbb", b"\x16"]]
    
inverse_s_box = [\
    [b"\x52", b"\x09", b"\x6a", b"\xd5", b"\x30", b"\x36", b"\xa5", b"\x38", b"\xbf", b"\x40", b"\xa3", b"\x9e", b"\x81", b"\xf3", b"\xd7", b"\xfb"], \
    [b"\x7c", b"\xe3", b"\x39", b"\x82", b"\x9b", b"\x2f", b"\xff", b"\x87", b"\x34", b"\x8e", b"\x43", b"\x44", b"\xc4", b"\xde", b"\xe9", b"\xcb"], \
    [b"\x54", b"\x7b", b"\x94", b"\x32", b"\xa6", b"\xc2", b"\x23", b"\x3d", b"\xee", b"\x4c", b"\x95", b"\x0b", b"\x42", b"\xfa", b"\xc3", b"\x4e"], \
    [b"\x08", b"\x2e", b"\xa1", b"\x66", b"\x28", b"\xd9", b"\x24", b"\xb2", b"\x76", b"\x5b", b"\xa2", b"\x49", b"\x6d", b"\x8b", b"\xd1", b"\x25"], \
    [b"\x72", b"\xf8", b"\xf6", b"\x64", b"\x86", b"\x68", b"\x98", b"\x16", b"\xd4", b"\xa4", b"\x5c", b"\xcc", b"\x5d", b"\x65", b"\xb6", b"\x92"], \
    [b"\x6c", b"\x70", b"\x48", b"\x50", b"\xfd", b"\xed", b"\xb9", b"\xda", b"\x5e", b"\x15", b"\x46", b"\x57", b"\xa7", b"\x8d", b"\x9d", b"\x84"], \
    [b"\x90", b"\xd8", b"\xab", b"\x00", b"\x8c", b"\xbc", b"\xd3", b"\x0a", b"\xf7", b"\xe4", b"\x58", b"\x05", b"\xb8", b"\xb3", b"\x45", b"\x06"], \
    [b"\xd0", b"\x2c", b"\x1e", b"\x8f", b"\xca", b"\x3f", b"\x0f", b"\x02", b"\xc1", b"\xaf", b"\xbd", b"\x03", b"\x01", b"\x13", b"\x8a", b"\x6b"], \
    [b"\x3a", b"\x91", b"\x11", b"\x41", b"\x4f", b"\x67", b"\xdc", b"\xea", b"\x97", b"\xf2", b"\xcf", b"\xce", b"\xf0", b"\xb4", b"\xe6", b"\x73"], \
    [b"\x96", b"\xac", b"\x74", b"\x22", b"\xe7", b"\xad", b"\x35", b"\x85", b"\xe2", b"\xf9", b"\x37", b"\xe8", b"\x1c", b"\x75", b"\xdf", b"\x6e"], \
    [b"\x47", b"\xf1", b"\x1a", b"\x71", b"\x1d", b"\x29", b"\xc5", b"\x89", b"\x6f", b"\xb7", b"\x62", b"\x0e", b"\xaa", b"\x18", b"\xbe", b"\x1b"], \
    [b"\xfc", b"\x56", b"\x3e", b"\x4b", b"\xc6", b"\xd2", b"\x79", b"\x20", b"\x9a", b"\xdb", b"\xc0", b"\xfe", b"\x78", b"\xcd", b"\x5a", b"\xf4"], \
    ["\x1f", b"\xdd", b"\xa8", b"\x33", b"\x88", b"\x07", b"\xc7", b"\x31", b"\xb1", b"\x12", b"\x10", b"\x59", b"\x27", b"\x80", b"\xec", b"\x5f"], \
    [b"\x60", b"\x51", b"\x7f", b"\xa9", b"\x19", b"\xb5", b"\x4a", b"\x0d", b"\x2d", b"\xe5", b"\x7a", b"\x9f", b"\x93", b"\xc9", b"\x9c", b"\xef"], \
    [b"\xa0", b"\xe0", b"\x3b", b"\x4d", b"\xae", b"\x2a", b"\xf5", b"\xb0", b"\xc8", b"\xeb", b"\xbb", b"\x3c", b"\x83", b"\x53", b"\x99", b"\x61"], \
    [b"\x17", b"\x2b", b"\x04", b"\x7e", b"\xba", b"\x77", b"\xd6", b"\x26", b"\xe1", b"\x69", b"\x14", b"\x63", b"\x55", b"\x21", b"\x0c", b"\x7d"]]

def get_sub_byte(b):
    return forward_s_box[get_most_significant_nibble(b)][get_least_significant_nibble(b)]
    
def get_inverse_sub_byte(b):
    return inverse_s_box[get_most_significant_nibble(b)][get_least_significant_nibble(b)]
    
def get_most_significant_nibble(b):
    return (int.from_bytes(b) & 0xf0) >> 4
    
def get_least_significant_nibble(b):
    return int.from_bytes(b) & 0x0f

def left_circular_bitshift(n):
    if len(n) != 1:
        raise ValueError("Argument must be a single byte.")
    result = (int.from_bytes(n) << 1) & 0xff
    return (result | get_most_significant_bit(n)).to_bytes()
    
def get_most_significant_bit(n):
    return (int.from_bytes(n) & 0x80) >> 7

def rot_word(word):
    word_length = len(word)
    return bytes(word[1:word_length] + word[0:1])

round_constants = [b"\x01\x00\x00\x00", b"\x02\x00\x00\x00", \
    b"\x04\x00\x00\x00", b"\x08\x00\x00\x00", \
    b"\x10\x00\x00\x00", b"\x20\x00\x00\x00", \
    b"\x40\x00\x00\x00", b"\x80\x00\x00\x00", \
    b"\x1B\x00\x00\x00", b"\x36\x00\x00\x00"]

def get_rc(n):
    if n < 1:
       raise ValueError("Round constant index cannot be less than 1.")
    if n > 10:
        raise ValueError("Round constant index cannot be greater than 10.") 
    
    index = n
    rc = 0
    if index == 1:
        return 1
        
    prev_rc = get_rc(index - 1)
    if prev_rc.to_bytes() < b"\x80":
        return prev_rc << 1
    else:
        rc = int.from_bytes(xor.fixed_length_xor(int.to_bytes(prev_rc << 1, length=2), b"\x01\x1B"))
        return rc
    
def get_round_constant(n):
    # this function exists to prove I can do it
    round_constant = bytearray(4)
    round_constant[0] = get_rc(n)
    return round_constant
    
