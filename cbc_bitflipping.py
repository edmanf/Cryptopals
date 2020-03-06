import aes
import re

key = aes.get_rand_aes_key(16)


def encrypt(input_string):
    prepend_string = b"comment1=cooking%20MCs;userdata="
    append_string = b";comment2=%20like%20a%20pound%20of%20bacon"
    return None


def sanitize(input_string):
    string = input_string.decode()
    return re.sub("([;=])", r"'\1'", string)


def is_admin(input_string):
    string = input_string.decode()
    contains = ";admin=true;" in string
    return contains
