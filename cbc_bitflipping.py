import aes
import re
import aes_oracle
import utils
import xor

key = aes.get_rand_aes_key(16)  # unknown to attacker
iv = aes.get_rand_aes_key(16)  # unknown to attacker


def get_malicious_ciphertext():
    diff_block_index = aes_oracle.get_diff_block_index(16, encrypt)
    num_pad_bytes = aes_oracle.get_num_prefix_bytes(diff_block_index, 16, encrypt)
    pad_bytes = bytearray("P", "utf-8") * num_pad_bytes

    pt_block = bytearray("\x00", "utf-8") * 16
    plaintext_input = pad_bytes + pt_block

    ciphertext = encrypt(plaintext_input)
    ct_blocks = utils.make_blocks(ciphertext, 16)
    target_ct_block = ct_blocks[diff_block_index + 1]

    payload = bytearray(";admin=true;", "utf-8")

    malicious_ct_block = xor.repeating_key_xor(target_ct_block, pt_block)
    malicious_ct_block = xor.repeating_key_xor(malicious_ct_block, payload)
    malicious_ct_block = xor.repeating_key_xor(malicious_ct_block, payload)


    ct_blocks[diff_block_index + 1] = malicious_ct_block
    return bytearray().join(ct_blocks)


def is_cipher_text_admin(cipher_text):
    plain_text = aes.aes_cbc_decrypt(cipher_text, key, iv)
    return is_admin(plain_text)


def encrypt(input_string):
    prepend_string = bytearray("comment1=cooking%20MCs;userdata=", "utf-8")
    append_string = bytearray(";comment2=%20like%20a%20pound%20of%20bacon", "utf-8")
    string = prepend_string + sanitize(input_string) + append_string
    return aes.aes_cbc_encrypt(bytearray(string), key, iv)


def sanitize(input_bytes):
    """
    Returns a sanitized version of the input bytes with ; and = surrounded by single quotes
    Args:
        input_bytes: a bytes-like object

    Returns: a new bytearray with ; and = characters surrounded with single quotes

    """
    return bytearray(re.sub("([;=])", r"'\1'", input_bytes.decode()), "utf-8")


def is_admin(input_bytes):
    return bytearray(";admin=true;", "utf-8") in input_bytes
