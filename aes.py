""" Methods for encryption and decryption."""

from enum import Enum

import utils
import xor
import convert

from Crypto.Cipher import AES
import Crypto.Random
from Crypto.Random import random

unknown_string_c12 = get_unknown_string_c12()
key_c12 = get_key_c12()


def simple_ecb_decryption():
    block_size = detect_ecb_oracle_block_size(key_c12)
    ct = simple_ecb_oracle(bytearray(), key_c12)
    
    pt = bytearray("A", "utf-8") * len(ct)
    pt_blocks = utils.make_blocks(pt, block_size)
    
    pt_dict = {}
    
    # build last byte dictionary
    for i in range(block_size):
        input = bytearray("A", "utf-8") * i
        ct = simple_ecb_oracle(input, key_c12)
        pt_dict[i] = utils.make_blocks(ct, block_size)
        
    # for each block
    # go through each last byte possible and save in pt
    # go through next block
        
    

def detect_ecb_oracle_block_size(key):
    """ Detects the block size of the simple_ecb_oracle. """
    block_size = 0
    pt = bytearray()
    base = simple_ecb_oracle(pt, key)
    while(True):
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
    
    pt = utils.PKCS7_pad(plaintext + unknown_string_c12, len(key))
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
        
def detect_aes_encryption_mode(ciphertext, key_length, repeat_threshold = 3):
    """ Takes a given ciphertext and detect whether its been encrypted
    in ecb or cbc mode.
    
    """
    a = utils.count_repeats(ciphertext, key_length)
    if utils.count_repeats(ciphertext, key_length) > 3:
        return Mode.ECB
    else:
        return Mode.CBC
    
    

def ecb_cbc_encryption_oracle(plaintext, mode = None):
    """ Encrypts plaintext with aes in either ecb or cbc mode
    
    If mode is not set, a random mode is chosen.
    """
    key = get_rand_aes_key()
    prefix = bytearray(
        Crypto.Random.get_random_bytes(random.randint(5,11)))
    suffix = bytearray(
        Crypto.Random.get_random_bytes(random.randint(5,11)))
    pt = prefix + plaintext + suffix
    
    ct = None
    
    chosen_mode = None
    if mode is None:
        chosen_mode = random.randint(0,1)
    else:
        chosen_mode = mode
        
    if chosen_mode is Mode.ECB:
        ct = aes_ecb_encrypt(utils.PKCS7_pad(pt, len(key)), key)
        return ECBCBCOracleCipher(ct, Mode.ECB)
    else:
        iv = bytearray(Crypto.Random.get_random_bytes(16))
        ct = aes_cbc_encrypt(pt, key, iv)
        return ECBCBCOracleCipher(ct, Mode.CBC)

def get_rand_aes_key(key_length = 16):
    return bytearray(Crypto.Random.get_random_bytes(key_length))
    

def aes_cbc_encrypt(plaintext, key, iv, pad_byte = b'\x04'):
    length = len(key)
    padded = utils.PKCS7_pad(plaintext, length, pad_byte)
    ciphertext = bytearray(len(padded))
    blocks = utils.make_blocks(padded, length)
    if len(blocks) == 0:
        return None
        
    vector = iv
    for i in range(len(blocks)):
        block = blocks[i]
        vector = aes_ecb_encrypt(xor.fixed_XOR(block, vector), key)
        ciphertext[i * length:(i + 1) * length] = vector
    return ciphertext
    
def aes_cbc_decrypt(ciphertext, key, iv):
    length = len(key)
    blocks = utils.make_blocks(ciphertext, length)
    plaintext = bytearray(len(ciphertext))
    
    vector = iv
    for i in range(len(blocks)):
        block = blocks[i]
        pt = xor.fixed_XOR(aes_ecb_decrypt(block, key), vector)
        plaintext[i * length:(i + 1) * length] = pt
        vector = block
    return plaintext

def detect_AES_ECB(ciphers, key_size):
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
    
    def __init__(self, ciphertext = None, mode = None):
        self.ciphertext = ciphertext
        self.mode = mode
        
class Mode(Enum):
    ECB = 0
    CBC = 1
    
    
def get_unknown_string_c12():
    f = open("res/12.txt")
    b64_text = f.read()
    f.close()
    unknown_string_c12 = convert.b64_string_to_bytes(b64_text)
    
def get_key_c12():
    f = open("res/12_secret.txt")
    key_c12 = convert.hex_string_to_bytes(f.read())
    f.close()
