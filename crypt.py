""" Methods for encryption and decryption."""

import utils

from Crypto.Cipher import AES

def detect_AES_ECB(ciphers, key_size):
    """ Detects the cipher that is most likely to have been encrypted by AES
    in ECB mode and returns it.
    """
    max_repeats = 0
    best_cipher = None
    for cipher in ciphers:
        block_counts = {}
        blocks = utils.make_blocks(cipher, key_size)
        for block in blocks:
            if block in block_counts:
                block_counts[block] += 1
            else:
                block_counts[block] = 0
        repeats = sum(block_counts.values())
        if repeats > max_repeats:
            max_repeats = repeats
            best_cipher = cipher
    return best_cipher
        
                

def aes_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext
    
