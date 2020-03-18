import cbc_padding_oracle
import aes
import utils

class TestSet3:
    def test_c17(self):
        assert False

class TestC17Misc:
    def test_known_plaintext(self):
        iv = bytearray(16)
        pt = utils.pkcs7_pad(bytearray("HELLO WORLD", "utf-8"), 16)
        key = bytearray(16)

        ct = aes.aes_cbc_encrypt(pt, key, iv)

        result = cbc_padding_oracle.CipherResult(ct, iv)

        pt = cbc_padding_oracle.padding_oracle_attack(result)