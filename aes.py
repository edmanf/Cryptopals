""" Methods for encryption and decryption."""

import utils
import xor

from Crypto.Cipher import AES

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
    
