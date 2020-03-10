import aes
import re
import aes_oracle
import utils
import xor

key = aes.get_rand_aes_key(16)  # unknown to attacker
iv = aes.get_rand_aes_key(16)   # unknown to attacker

def get_malicious_ciphertext():
    diff_block_index = aes_oracle.get_diff_block_index(16, encrypt)
    num_prefix_bytes = aes_oracle.get_num_prefix_bytes(diff_block_index, 16, encrypt)
    pad_bytes = bytearray("P", "utf-8") * (16 - num_prefix_bytes)

    target_pt_block = bytearray("A", "utf-8") * 16
    plaintext_input = pad_bytes + target_pt_block

    ciphertext = encrypt(plaintext_input)
    ct_blocks = utils.make_blocks(ciphertext, 16)
    target_ct_block = ct_blocks[diff_block_index]

    payload = bytearray(";admin=true;", "utf-8")

    malicious_ct_block = xor.repeating_key_xor(target_ct_block, payload)
    ct_blocks[diff_block_index] = malicious_ct_block
    return bytearray().join(ct_blocks)


def is_cipher_text_admin(cipher_text):
    plain_text = aes.aes_cbc_decrypt(cipher_text, key)
    return is_admin(plain_text)


def encrypt(input_string):
    prepend_string = bytearray("comment1=cooking%20MCs;userdata=", "utf-8")
    append_string = bytearray(";comment2=%20like%20a%20pound%20of%20bacon", "utf-8")
    string = prepend_string + bytes(sanitize(input_string), "utf-8") + append_string
    return aes.aes_cbc_encrypt(bytearray(string), key, iv)


def sanitize(input_string):
    return re.sub("([;=])", r"'\1'", input_string)


def is_admin(input_string):
    return b";admin=true;" in input_string
