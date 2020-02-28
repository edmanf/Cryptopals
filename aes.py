""" Methods for encryption and decryption."""

from enum import Enum

import utils
import xor
import convert

from Crypto.Cipher import AES
import Crypto.Random
from Crypto.Random import random

unknown_string_c12 = None
key_c12 = None
hard_ecb_prefix = None


def hard_ecb_oracle_decryption():
    key = get_key_c12()
    base = hard_ecb_oracle(bytearray(), key)
    base_len = len(base)

    # find block length
    block_len = base_len
    for i in range(base_len):
        pt = bytearray("A", "utf-8") * i
        ct = hard_ecb_oracle(pt, key)
        if len(ct) != block_len:
            block_len = len(ct) - base_len
            break

    # find first changing block index
    # this is the first block that contains user input
    diff_block_index = get_diff_block_index(block_len, key, hard_ecb_oracle)

    # find how many bytes it takes to make the block stop
    # changing. This will mean rand_prefix has been padded (with 1 extra)
    num_prefix_pad_bytes = get_num_prefix_bytes(
        diff_block_index, block_len, key, hard_ecb_oracle)

    num_prefix_bytes = diff_block_index * block_len - num_prefix_pad_bytes
    unknown_string_length = detect_unknown_length(key, hard_ecb_oracle) - num_prefix_bytes

    pad_bytes = bytearray("A", "utf-8") * num_prefix_pad_bytes

    ct_dict = {}

    # build last byte dictionary
    for i in range(block_len):
        pt = pad_bytes + bytes("A", "utf-8") * i
        ct = hard_ecb_oracle(pt, key)
        ct_dict[bytes(pt)] = ct

    plaintext = bytearray("A", "ascii") * unknown_string_length

    # for each block
    # go through each last byte possible and save in pt
    # go through next block
    for i in range(unknown_string_length):

        num_input_bytes = (block_len - (i + 1)) % block_len
        pt = bytearray("A", "utf-8") * num_input_bytes

        ct = ct_dict[bytes(pt)]

        # find the byte that makes a matching block
        for j in range(256):
            test_byte = bytes([j])

            if i < block_len:
                # input + solved bytes + test byte for first block
                start = diff_block_index * block_len
                end = block_len - num_input_bytes - 1
                test_input = pt + plaintext[start:end] + test_byte
            else:
                # solved bytes + test byte for all other blocks
                start = i - block_len + 1
                end = start + block_len - 1
                test_input = plaintext[start:end] + test_byte

            test_ct = simple_ecb_oracle(test_input, key)

            if i < block_len:
                ct_start = diff_block_index * block_len
            else:
                ct_start = start + num_input_bytes

            if ct[ct_start:ct_start + block_len] == test_ct[:block_len]:
                plaintext[i] = j  # k = test_byte
                break

        return plaintext


def get_num_prefix_bytes(diff_block_index, block_len, key, function):
    """ Returns the number of bytes in the ciphertext taken by the encryption function before the bytes
    controlled by user input.

    Args:
        diff_block_index: The index of the first ciphertext block that changes with user input
        block_len: length of blocks used by the encryption function
        key: the key used for the encryption function
        function: the encryption function that takes a bytearray as the first function and the key as the second

    Returns:

    """
    target_ct = function(bytearray(b'\xff') * block_len * 4, key)
    target_ct_blocks = utils.make_blocks(target_ct, block_len)
    target_block = target_ct_blocks[diff_block_index + 1]

    for i in range(1, block_len):
        pt = bytearray(b'\xff') * (i + block_len)  # i is for padding, block_len bytes to match target_block
        ct = utils.make_blocks(function(pt, key), block_len)
        block = ct[diff_block_index + 1]
        if block == target_block:
            return i

    return 0  # if not 1 through block_len, it must be 0


def get_diff_block_index(block_len, key, encryption_function):
    """ Returns the index of the first block that is different when running an encryption function against
    an empty bytearray, and one with a single byte of input.

    i.e. return the first i such that hard_ecb_oracle(bytearray())[i] != hard_ecb_oracle(bytearray(\x01))[i]

    Args:
        encryption_function: an encryption function that takes bytearray as the first function and a key as the second
        block_len: length of the block
        key: the key to run hard_ecb_oracle() under

    Returns: The index of the first block where running hard_ecb_oracle against an empty bytearray and a size 1
    bytearray is different.

    """
    base_blocks = utils.make_blocks(encryption_function(bytearray(), key), block_len)
    single_byte_input = utils.make_blocks(
        encryption_function(bytearray(b'\x01'), key),
        block_len)

    for i in range(len(base_blocks)):
        if base_blocks[i] != single_byte_input[i]:
            return i

    return len(base_blocks)


def hard_ecb_oracle(message, key):
    """
    Returns the result of encrypting a string of random bytes with the given message and a preset
    unknown string, in that order.

    Args:
        message: the user chosen part of the plaintext
        key: the AES encryption key

    Returns: A ciphertext

    """

    # No target or key instructions given, so use the same as in c12
    unknown_string = get_unknown_string_c12()

    pt = bytearray()
    pt += get_hard_ecb_oracle_key() + bytearray(message) + unknown_string
    return aes_ecb_encrypt(utils.pkcs7_pad(pt, len(key)), key)


def get_hard_ecb_oracle_key():
    global hard_ecb_prefix

    if not hard_ecb_prefix:
        rand_prefix_max = 64
        rand_prefix_length = random.randint(0, rand_prefix_max)
        hard_ecb_prefix = get_rand_aes_key(rand_prefix_length)

    return hard_ecb_prefix


def simple_ecb_oracle_decryption():
    """


    Returns:

    """
    key = get_key_c12()
    block_size = detect_ecb_oracle_block_size(key)

    ct_dict = {}

    # build last byte dictionary
    for i in range(block_size):
        pt = bytes("A", "utf-8") * i
        ct = simple_ecb_oracle(pt, key)
        ct_dict[pt] = ct

    length = detect_unknown_length(key, simple_ecb_oracle)
    plaintext = bytearray("A", "utf-8") * length

    # for each block
    # go through each last byte possible and save in pt
    # go through next block
    for i in range(length):

        num_input_bytes = (block_size - (i + 1)) % block_size
        pt = bytearray("A", "utf-8") * num_input_bytes

        ct = ct_dict[bytes(pt)]

        # find the byte that makes a matching block
        for j in range(256):
            test_byte = bytes([j])

            if i < block_size:
                # input + solved bytes + test byte for first block
                start = 0
                end = block_size - num_input_bytes - 1
                test_input = pt + plaintext[start:end] + test_byte
            else:
                # solved bytes + test byte for all other blocks
                start = i - block_size + 1
                end = start + block_size - 1
                test_input = plaintext[start:end] + test_byte

            test_ct = simple_ecb_oracle(test_input, key)

            if i < block_size:
                ct_start = 0
            else:
                ct_start = start + num_input_bytes

            if ct[ct_start:ct_start + block_size] == test_ct[:block_size]:
                plaintext[i] = j  # k = test_byte
                break
    return plaintext


def detect_unknown_length(key, oracle_function):
    """
    Returns the number of unknown bytes present used in the given oracle function

    Args:
        key:
        oracle_function:

    Returns:

    """
    extra = 0
    ct = oracle_function(bytearray(), key)
    length = len(ct)
    while True:
        extra += 1
        pt = bytearray("A", "utf-8") * extra
        ct = oracle_function(pt, key)
        if len(ct) > length:
            # new block made, too many extra input bytes
            return length - (extra - 1)


def detect_ecb_oracle_block_size(key):
    """ Detects the block size of the simple_ecb_oracle. """
    block_size = 0
    pt = bytearray()
    base = simple_ecb_oracle(pt, key)
    while True:
        pt += bytearray("A", "utf-8")
        block_size += 1
        ct = simple_ecb_oracle(pt, key)
        if ct[len(pt):] == base:
            # if all bytes after the inserted one are the same as the base,
            # then the extra bytes have created one block
            return block_size


def simple_ecb_oracle(plaintext, key):
    """ Appends plaintext with a hidden message and encrypts it under
    aes in ecb mode with the given key. """
    unknown_string = get_unknown_string_c12()

    pt = utils.pkcs7_pad(bytearray(plaintext) + unknown_string, len(key))
    ct = aes_ecb_encrypt(pt, key)
    return ct


def ecb_cbc_detection_oracle():
    """ Detects the block cipher mode of the ecb cbc encryption oracle and return the result. """

    # The difference between ECB and CBC is that ECB will have the same
    # output for the same input. A sufficiently long input of the same
    # byte will produce equal ciphertext blocks in ECB mode.
    plaintext = bytearray("A", "utf-8") * 512
    result = ecb_cbc_encryption_oracle(plaintext)
    mode = detect_aes_encryption_mode(result.ciphertext, 16)
    return mode


def detect_aes_encryption_mode(ciphertext, key_length, repeat_threshold=3):
    """ Takes a given ciphertext and detect whether its been encrypted
    in ecb or cbc mode.
    
    """

    if utils.count_repeats(ciphertext, key_length) > repeat_threshold:
        return Mode.ECB
    else:
        return Mode.CBC


def ecb_cbc_encryption_oracle(plaintext, mode=None):
    """ Encrypts plaintext with aes in either ecb or cbc mode
    
    If mode is not set, a random mode is chosen.
    """
    key = get_rand_aes_key()
    prefix = bytearray(
        Crypto.Random.get_random_bytes(random.randint(5, 11)))
    suffix = bytearray(
        Crypto.Random.get_random_bytes(random.randint(5, 11)))
    pt = prefix + plaintext + suffix

    if mode is None:
        chosen_mode = random.randint(0, 1)
    else:
        chosen_mode = mode

    if chosen_mode is Mode.ECB:
        ct = aes_ecb_encrypt(utils.pkcs7_pad(pt, len(key)), key)
        return ECBCBCOracleCipher(ct, Mode.ECB)
    else:
        iv = bytearray(Crypto.Random.get_random_bytes(16))
        ct = aes_cbc_encrypt(pt, key, iv)
        return ECBCBCOracleCipher(ct, Mode.CBC)


def get_rand_aes_key(key_length=16):
    return utils.get_random_bytes(key_length)


def aes_cbc_encrypt(plaintext, key, iv):
    length = len(key)
    padded = utils.pkcs7_pad(plaintext, length)
    ciphertext = bytearray(len(padded))
    blocks = utils.make_blocks(padded, length)
    if len(blocks) == 0:
        return None

    vector = iv
    for i in range(len(blocks)):
        block = blocks[i]
        vector = aes_ecb_encrypt(xor.fixed_xor(block, vector), key)
        ciphertext[i * length:(i + 1) * length] = vector
    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    length = len(key)
    blocks = utils.make_blocks(ciphertext, length)
    plaintext = bytearray(len(ciphertext))

    vector = iv
    for i in range(len(blocks)):
        block = blocks[i]
        pt = xor.fixed_xor(aes_ecb_decrypt(block, key), vector)
        plaintext[i * length:(i + 1) * length] = pt
        vector = block
    return plaintext


def detect_aes_in_ecb_mode(ciphers, key_size):
    """ Detects the cipher that is most likely to have been encrypted by AES
    in ECB mode and returns it.
    """
    max_repeats = 0
    best_cipher = None
    for cipher in ciphers:
        repeats = utils.count_repeats(cipher, key_size)
        if repeats > max_repeats:
            max_repeats = repeats
            best_cipher = cipher
    return best_cipher


def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext


class ECBCBCOracleCipher:
    ciphertext = None
    mode = None

    def __init__(self, ciphertext=None, mode=None):
        self.ciphertext = ciphertext
        self.mode = mode


class Mode(Enum):
    ECB = 0
    CBC = 1


def get_unknown_string_c12():
    """ Returns the unknown string that is appended to the plaintext
    in the ecb oracle. """
    global unknown_string_c12
    if unknown_string_c12 is None:
        f = utils.res_file_open("12.txt")
        b64_text = f.read()
        f.close()
        unknown_string_c12 = convert.b64_string_to_bytes(b64_text)
    return unknown_string_c12


def get_key_c12():
    """ Returns the random but consistent key used for the ecb oracle. """
    global key_c12
    if key_c12 is None:
        f = utils.res_file_open("12_secret.txt")
        key_c12 = convert.hex_string_to_bytes(f.read())
        f.close()
    return key_c12
