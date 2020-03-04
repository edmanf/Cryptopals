""" Methods for encryption and decryption."""

import utils
import xor

from Crypto.Cipher import AES


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


def aes_ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext


def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext
