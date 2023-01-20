from src.cryptopals import xor

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
    # this function exists to prove 
    round_constant = bytearray(4)
    round_constant[0] = get_rc(n)
    return round_constant
    
