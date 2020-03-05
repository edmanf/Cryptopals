import pytest

import aes_oracle
import utils
import convert
import aes
from KVParser import KVParser
import profile_for_attack as pfa


class TestSet2:
    def test_c9(self):
        """ Implement PKCS#7 padding"""
        message = bytearray("YELLOW SUBMARINE", "utf-8")
        pad_length = 20
        expected = "YELLOW SUBMARINE\x04\x04\x04\x04"
        actual = utils.pkcs7_pad(message, pad_length)
        assert actual.decode() == expected

        message = bytearray("YELLOW SUBMARINE", "utf-8")
        pad_length = 16
        expected = "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
        actual = utils.pkcs7_pad(message, pad_length)
        assert actual.decode() == expected

        message = bytearray("HELLO WORLD", "utf-8")
        pad_length = 16
        expected = "HELLO WORLD\x05\x05\x05\x05\x05"
        actual = utils.pkcs7_pad(message, pad_length)
        assert actual.decode() == expected

    def test_c10(self):
        """ Implement CBC mode. """
        input_file = "10.txt"
        expected_file = "10_expected.txt"

        f = utils.res_file_open(expected_file)
        expected = f.read()
        f.close()

        f = utils.res_file_open(input_file)
        b64_text = f.read()
        f.close()

        input_pt = convert.b64_string_to_bytes(b64_text)
        key = bytearray("YELLOW SUBMARINE", "utf-8")
        iv = bytes("\x00", "ascii") * len(key)
        actual = aes.aes_cbc_decrypt(input_pt, key, iv)
        assert actual.decode() == expected

    def test_c11(self):
        """ An ECB/CBC detection oracle. """
        plaintext = bytearray("A", "utf-8") * 256
        result = aes_oracle.ecb_cbc_encryption_oracle(plaintext,
                                                      mode=aes_oracle.Mode.ECB)
        mode = aes_oracle.detect_aes_encryption_mode(result.ciphertext, 16)
        assert mode == aes_oracle.Mode.ECB

        result = aes_oracle.ecb_cbc_encryption_oracle(plaintext,
                                                      mode=aes_oracle.Mode.CBC)
        mode = aes_oracle.detect_aes_encryption_mode(result.ciphertext, 16)
        assert mode == aes_oracle.Mode.CBC

    def test_c12(self):
        """ Byte-at-a-time ECB decryption (Simple) """
        expected = aes_oracle.get_unknown_string_c12().decode()
        actual = aes_oracle.simple_ecb_oracle_decryption().decode()

        assert actual == expected

    def test_c13(self):
        """ ECB cut-and-paste """
        profile = pfa.profile_attack()
        assert profile.get(bytes("role", "utf-8")) == bytes("admin", "utf-8")

    def test_c14(self):
        """ Byte-at-a-time ECB decryption (Harder). """
        expected = aes_oracle.get_unknown_string_c12().decode()

        assert aes_oracle.hard_ecb_oracle_decryption().decode() == expected

    def test_c15(self):
        """ PKCS#7 padding validation. """
        string = "ICE ICE BABY\x04\x04\x04\x04"
        assert utils.is_valid_pkcs7(string) is True

        with pytest.raises(ValueError):
            string = "ICE ICE BABY\x05\x05\x05\x05"
            utils.is_valid_pkcs7(string)

        with pytest.raises(ValueError):
            string = "ICE ICE BABY\x01\x02\x03\x04"
            utils.is_valid_pkcs7(string)

        with pytest.raises(ValueError):
            string = "ICE ICE BABY"
            utils.is_valid_pkcs7(string)

        with pytest.raises(ValueError):
            string = "A\x00"
            utils.is_valid_pkcs7(string)

        string = "\x01\x01"  # "\x01" padded to length 1
        assert utils.is_valid_pkcs7(string) is True

        string = "\x01"  # "" padded to length 1
        assert utils.is_valid_pkcs7(string) is True

        with pytest.raises(ValueError):
            string = "\x02"
            utils.is_valid_pkcs7(string)

        string = "YELLOW SUBMARINE\x04\x04\x04\x04"
        assert utils.is_valid_pkcs7(string) is True

        with pytest.raises(ValueError):
            string = "YELLOW SUBMARINE\x05\x05\x05\x05"
            utils.is_valid_pkcs7(string)


class TestMisc:
    def test_hard_ecb_random_prefix(self):
        assert aes_oracle.get_hard_ecb_oracle_prefix() == aes_oracle.get_hard_ecb_oracle_prefix()
        assert aes_oracle.get_hard_ecb_oracle_prefix() is not None

    def test_hard_ecb_get_num_prefix_bytes(self):
        block_len = 16
        key = aes.get_rand_aes_key(block_len)

        pre = 14
        def oracle(x): return aes.aes_ecb_encrypt(utils.pkcs7_pad(bytearray(b'\xee') * pre + x, block_len), key)

        diff_block_index = 0
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 2

        pre = 6
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 10

        pre = 0
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 0

        pre = 15
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 1

        diff_block_index = 1
        pre = 20
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 12

        pre = 16
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 0

        pre = 31
        assert aes_oracle.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 1

    def test_hard_ecb_diff_block_index(self):
        block_len = 16
        key = aes.get_rand_aes_key(block_len)

        pre = 4

        def oracle(x): return aes.aes_ecb_encrypt(utils.pkcs7_pad(bytearray(b'\x01') * pre + x, block_len), key)

        assert aes_oracle.get_diff_block_index(block_len, oracle) == 0

        pre = 0
        assert aes_oracle.get_diff_block_index(block_len, oracle) == 0

        pre = 15
        assert aes_oracle.get_diff_block_index(block_len, oracle) == 0

        pre = 20
        assert aes_oracle.get_diff_block_index(block_len, oracle) == 1

        pre = 16
        assert aes_oracle.get_diff_block_index(block_len, oracle) == 1

        pre = 31
        assert aes_oracle.get_diff_block_index(block_len, oracle) == 1

        pre = 32
        assert aes_oracle.get_diff_block_index(block_len, oracle) == 2


    def test_detect_oracle_block_size(self):
        block_size = 16

        actual = aes_oracle.detect_ecb_oracle_block_size(aes_oracle.simple_ecb_oracle)
        assert actual == block_size

        actual = aes_oracle.detect_ecb_oracle_block_size(aes_oracle.hard_ecb_oracle)
        assert actual == block_size

    def test_ecb_oracle_encryption_mode(self):
        key = aes.get_rand_aes_key(16)
        pt = bytearray("A", "utf-8") * 256
        expected = aes_oracle.Mode.ECB

        actual = aes_oracle.detect_aes_encryption_mode(aes_oracle.simple_ecb_oracle(pt), len(key))
        assert actual == expected

    def test_kvparser(self):
        args = bytearray("foo=HELLO&bar=WORLD", "utf-8")
        assert KVParser(args).get_repr() == args

        args = bytearray("foo=HELLO", "utf-8")
        assert KVParser(args).get_repr() == args

    def test_profile_for(self):
        input_email = bytearray("foo@bar.com", "utf-8")
        expected = "email=foo@bar.com&uid=10&role=user"
        assert KVParser.profile_for(input_email).to_string() == expected

    def test_email_sanitizer(self):
        input_email = bytearray("foo@bar.com&role=admin", "utf-8")
        expected_sanitize = bytearray("foo@bar.comroleadmin", "utf-8")
        assert KVParser.sanitize_email(input_email) == expected_sanitize

        expected = bytearray(
            "email=foo@bar.comroleadmin&uid=10&role=user",
            "utf-8")
        assert KVParser.profile_for(input_email).to_string() == expected.decode()

    def test_kvparser_enc_dec(self):
        input_email = bytearray("foo@bar.com", "utf-8")
        expected = "email=foo@bar.com&uid=10&role=user"
        key = bytearray("YELLOW SUBMARINE", "utf-8")

        ct = KVParser.profile_for(input_email).encrypt(key)
        parser = KVParser.decrypt_profile(ct, key)
        assert parser.to_string() == expected

        input_email = bytearray("foo@bar.com&role=admin", "utf-8")
        expected = "email=foo@bar.comroleadmin&uid=10&role=user"
        ct = KVParser.profile_for(input_email).encrypt(key)
        parser = KVParser.decrypt_profile(ct, key)
        assert parser.to_string() == expected
