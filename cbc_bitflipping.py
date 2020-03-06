import aes
import re
import convert

key = aes.get_rand_aes_key(16)


def is_cipher_text_admin(cipher_text):
    plain_text = aes.aes_cbc_decrypt(cipher_text, key)
    return is_admin(plain_text)


def encrypt(input_string):
    prepend_string = bytearray("comment1=cooking%20MCs;userdata=", "utf-8")
    append_string = bytearray(";comment2=%20like%20a%20pound%20of%20bacon", "utf-8")
    string = prepend_string + bytes(sanitize(input_string), "utf-8") + append_string
    return aes.aes_cbc_encrypt(bytearray(string), key, aes.get_rand_aes_key(16))


def sanitize(input_string):
    return re.sub("([;=])", r"'\1'", input_string)


def is_admin(input_string):
    return b";admin=true;" in input_string
