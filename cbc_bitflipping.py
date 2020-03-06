import aes
import re

key = aes.get_rand_aes_key(16)


def is_cipher_text_admin(cipher_text):
    plain_text = aes.aes_cbc_decrypt(cipher_text, key)
    return is_admin(plain_text)


def encrypt(input_string):
    prepend_string = b"comment1=cooking%20MCs;userdata="
    append_string = b";comment2=%20like%20a%20pound%20of%20bacon"
    string = prepend_string + sanitize(input_string) + append_string
    return aes.aes_cbc_encrypt(bytearray(string), key, aes.get_rand_aes_key(16))


def sanitize(input_string):
    string = input_string.decode()
    return bytes(re.sub("([;=])", r"'\1'", string), "utf-8")


def is_admin(input_string):
    return b";admin=true;" in input_string
