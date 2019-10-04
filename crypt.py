""" Methods for encryption and decryption."""

import utils
import sys

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
    
def fixed_XOR(a, b):
    """ XOR two equal length buffers and return the result.
    
    Keyword arguments:
    a -- a bytes object
    b -- a bytes object
    """
    result = bytearray(b)
    for i in range(len(a)):
        result[i] = a[i] ^ b[i]
    return result
    
def single_byte_XOR(enc):
    """ Decrypts a cipher which has been XOR'd with a single character and
    returns a result containing the key and result.
    
    Keyword arguments:
    enc -- the cipher text
    """
    best_score = sys.maxsize
    best_key = None
    plain = None
    
    length = len(enc)
    for i in range(0, 256):
        key = bytearray(length)
        key[0:length] = [i] * length
        res = fixed_XOR(enc, key)
        score = utils.get_chi_square_value(res)
        if (score < best_score):
            best_score = score
            best_key = i
            plain = res
    return SingleByteXORResult(best_key, best_score, plain)
    
def detect_single_character_XOR(messages):
    """ Detects the most likely message to have been encrypted with
    single-character XOR and returns the decryption result.
    
    Keyword arguments:
    messages -- a list of messages where one has been encrypted with
        single-character XOR
    """
    best_result = SingleByteXORResult()
    for message in messages:
        result = single_byte_XOR(message)
        if result.score < best_result.score:
            print(result.message)
            best_result = result
    return best_result
    
def repeating_key_XOR(plaintext, key):
    length = len(plaintext)
    cipher = bytearray(length)
    for i in range(length):
        cipher[i] = plaintext[i] ^ key[i % len(key)]
    return cipher
    
def decrypt_repeating_key_XOR(ciphertext):
    num_key_sizes = 4
    avg_hds = []
    # find key size
    for i in range(2, 40): # size range from instructions
        sum_norm_hd = 0
        num_blocks = len(ciphertext) // i
        # can have i step size for more data points
        for j in range(0, num_blocks // 2, 2):
            a = ciphertext[j * i:(j + 1) * i]
            b = ciphertext[(j + 1) * i:(j + 2) * i]
            sum_norm_hd += utils.get_hamming_distance(a, b) / i
        avg_hds.append((i, sum_norm_hd / (len(ciphertext) // (2 * i))))
    
    avg_hds.sort(key = lambda tup : tup[1]) # sort by avg hd ascending
    key_sizes = [x[0] for x in avg_hds[0:num_key_sizes]] # take best key sizes
    
    # find best key for each key size
    keys = []
    for key_size in key_sizes:
        blocks = utils.make_blocks(ciphertext, key_size)
            
        transp_blocks = utils.transpose(blocks)
        
        key = bytearray()
        for block in transp_blocks:
            res = single_byte_XOR(block)
            key.append(res.key)
        keys.append(key)

    # get result of decrypting with each key_size key
    results = []
    for key in keys:
        results.append(repeating_key_XOR(ciphertext, key))
    results.sort(key = utils.get_chi_square_value)
    return results[0]

class SingleByteXORResult:
    """ This class represents the result of decrypting a message using single
    byte XOR.
    
    instance variables:
    key -- the byte that was used to decrypt the message
    message -- the unencrypted message
    score -- the chi-squared statistic value for the decrypted message
    """
    key = None
    message = None
    score = None
    
    def __init__(self, key=None, score=sys.maxsize, message=None):
        self.key = key
        self.score = score
        self.message = message