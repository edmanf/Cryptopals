import secrets

""" A collection of utility functions. """


def is_byte_letter(b):
    return is_byte_lowercase_letter(b) or is_byte_uppercase_letter(b)


def is_byte_uppercase_letter(b):
    return ord("Z") >= b >= ord("A")


def is_byte_lowercase_letter(b):
    return ord("z") >= b >= ord("a")


def count_repeats(msg, block_length):
    """ Returns the count of repeated blocks of size block_length in the given message. """

    block_counts = {}
    blocks = make_blocks(msg, block_length)
    for block in blocks:
        b = bytes(block)
        if b in block_counts:
            block_counts[b] += 1
        else:
            block_counts[b] = 0
    return sum(block_counts.values())


def pkcs7_pad(message, pad_length):
    """
    Returns a message that has been padded to a multiple of pad_length by appending it with N bytes,
    where the value of each byte will be the number of bytes added, N. If the
    message is already at the pad_length, an entire block of padding bytes will be added.

    Args:
        message: The message for padding.
        pad_length: The length that the message should be a multiple of.

    Returns: A padded version of the message.

    """

    padded = message.copy()
    diff = len(message) % pad_length

    if diff > 0:
        num_pad_bytes = pad_length - diff
    elif diff == 0:
        num_pad_bytes = pad_length

    pad_byte = bytes(chr(num_pad_bytes), "ascii")
    padded += pad_byte * num_pad_bytes
    return padded


def is_valid_pkcs7(message):
    error_message = "Invalid PKCS#7 padding."
    last_byte = message[-1:]
    last_byte_num = ord(last_byte)
    length = len(message)

    if last_byte_num > length:
        raise ValueError(error_message)

    match_count = 1
    for i in range(1, last_byte_num):
        if message[length - i - 1] == last_byte:
            match_count += 1
        else:
            raise ValueError(error_message)

    if match_count == last_byte_num:
        return True

    raise ValueError(error_message)


def get_hamming_distance(a, b):
    """ Compute the hamming distance between two strings as bytes-like and return it.
    Hamming distance is the number of different bits between strings.
    a and b must be of the same length
    """

    hd = 0
    for i in range(len(a)):
        diff = a[i] ^ b[i]  # all bit differences will be 1
        for j in range(8):
            # mask each bit and find number of 1s
            if diff & (1 << j) is not 0:
                hd = hd + 1
    return hd


def get_chi_square_value(text):
    """ Computes the chi square value of the bytes compared to average
    English text and returns the value. Smaller values mean the bytes more
    closely resemble English.
    
    Keyword arguments:
    text -- the bytearray you want to measure for resemblance to English
    """

    # Values if ignoring non-alphabetic characters and spaces is desired
    # behavior.
    alpha_freq = [
        0.0651738, 0.0124248, 0.0217339, 0.0349835, 0.1041442, 0.0197881, 0.0158610,
        0.0492888, 0.0558094, 0.0009033, 0.0050529, 0.0331490, 0.0202124, 0.0564513,
        0.0596302, 0.0137645, 0.0008606, 0.0497563, 0.0515760, 0.0729357, 0.0225134,
        0.0082903, 0.0171272, 0.0013692, 0.0145984, 0.0007836]
    space_freq = 0.1918182
    unexpected_freq = 0.0001  # decided by client

    # Values if you don't want to ignore other non-alphabetic letters
    # and spaces.
    #
    # alpha_freq = [ 
    # 0.0609, 0.0105, 0.0284, 0.0292, 0.1136, 0.0179, 0.0138,
    # 0.0341, 0.0544, 0.0024, 0.0041, 0.0292, 0.0276, 0.0544, 
    # 0.0600, 0.0195, 0.0024, 0.0495, 0.0568, 0.0803, 0.0243, 
    # 0.0097, 0.0138, 0.0024, 0.0130, 0.0003]
    # space_freq = 0.1217
    # other_freq = 0.0657

    counts = [0] * 28  # First 26 spots for alphas, 27 for spaces, 28 for other
    length = len(text)

    for i in range(length):
        c = text[i]
        if is_byte_lowercase_letter(c):
            index = c - ord('a')
            counts[index] = counts[index] + 1
        elif is_byte_uppercase_letter(c):
            index = c - ord('A')
            counts[index] = counts[index] + 1
        elif c == ord(' '):
            counts[26] = counts[26] + 1
        else:
            counts[27] = counts[27] + 1

    # Compute the chi square statistic of the letters and return it.
    res = 0
    for i in range(len(alpha_freq)):
        expected = length * alpha_freq[i]
        res = res + ((counts[i] - expected) ** 2) / expected

    expected = length * space_freq
    res = res + ((counts[26] - expected) ** 2) / expected

    expected = length * unexpected_freq
    res = res + ((counts[27] - expected) ** 2) / expected
    return res


def transpose(blocks):
    """ Transpose a list of mutable sequences and return it.
    The ith returned transposed block will be composed of the ith element
    of each of the blocks such that
    
    transposed_blocks[i] = [blocks[0][i], blocks[1][i],...]
    """
    transp_blocks = []
    for i in range(len(blocks[0])):  # 0-3
        transp_block = bytearray()
        for block in blocks:  # 4 blocks
            if i < len(block):  # last blocks may not have equal length
                transp_block.append(block[i])
        transp_blocks.append(transp_block)
    return transp_blocks


def make_blocks(msg, key_size):
    """ Return a list of blocks created by breaking the message into groups of size key_size.

    If the size of whole is not divisible by key_size, the leftover bytes in whole are not
    included. """
    blocks = []
    for i in range(len(msg) // key_size):
        block = msg[i * key_size:i * key_size + key_size]
        blocks.append(block)

    return blocks


def res_file_open(filename):
    """ Opens the file from the res folder and returns the stream """
    base = "res/"
    try:
        return open(base + filename)
    except FileNotFoundError:
        return open("../" + base + filename)


def get_random_bytes(length=16):
    """ Return a bytearray with random bytes of given length. """
    return bytearray(secrets.token_bytes(length))
