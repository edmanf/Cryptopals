import aes
import random
import utils

_AES_KEY = aes.get_rand_aes_key(16)

def get_ciphertext():
    file_path = "res/17.txt"
    f = open(file_path)
    lines = f.readlines()
    f.close()

    line = bytearray(random.Random().choice(lines), "utf-8")
    iv = aes.get_rand_aes_key(16)
    ciphertext = aes.aes_cbc_encrypt(utils.pkcs7_pad(line, 16), _AES_KEY, iv)
    return CipherResult(ciphertext, iv)


def is_padding_valid(cipher_result):
    pt = aes.aes_cbc_decrypt(cipher_result.ciphertext, _AES_KEY, cipher_result.iv)
    return utils.is_valid_pkcs7(pt)


def padding_oracle_attack(cipher_result = get_ciphertext()):
    ct = cipher_result.ciphertext
    iv = cipher_result.iv

    ct_blocks = utils.make_blocks(ct, 16)

    pt_blocks = ct_blocks.copy()

    pt = pt_blocks[0]
    for i in range(len(pt_blocks[0])):
        byte_index = len(pt) - (i + 1)
        for byte in range(256):
            block = ct_blocks[0]
            block[byte_index] = byte
            blocks = ct_blocks[1:]
            blocks.insert(0, block)
            pt = bytearray().join(blocks)
            if is_padding_valid():
                return pt

    return None




class CipherResult:
    def __init__(self, ciphertext, iv):
        self.ciphertext = ciphertext
        self.iv = iv
