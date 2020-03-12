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


def padding_oracle_attack():
    result = get_ciphertext()
    ct = result.ciphertext
    iv = result.iv


class CipherResult:
    def __init__(self, ciphertext, iv):
        self.ciphertext = ciphertext
        self.iv = iv
