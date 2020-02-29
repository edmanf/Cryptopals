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
        expected = "YELLOW SUBMARINE"
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
        result = aes.ecb_cbc_encryption_oracle(plaintext,
                                               mode=aes.Mode.ECB)
        mode = aes.detect_aes_encryption_mode(result.ciphertext, 16)
        assert mode == aes.Mode.ECB

        result = aes.ecb_cbc_encryption_oracle(plaintext,
                                               mode=aes.Mode.CBC)
        mode = aes.detect_aes_encryption_mode(result.ciphertext, 16)
        assert mode == aes.Mode.CBC

    def test_c12(self):
        """ Byte-at-a-time ECB decryption (Simple) """
        expected = aes.get_unknown_string_c12().decode()

        assert aes.simple_ecb_oracle_decryption().decode() == expected

    def test_c13(self):
        """ ECB cut-and-paste """
        profile = pfa.profile_attack()
        assert profile.get(bytes("role", "utf-8")) == bytes("admin", "utf-8")

    def test_c14(self):
        """ Byte-at-a-time ECB decryption (Harder). """
        expected = aes.get_unknown_string_c12().decode()

        assert aes.hard_ecb_oracle_decryption().decode() == expected


class TestMisc:
    def test_hard_ecb_random_prefix(self):
        assert aes.get_hard_ecb_oracle_prefix() == aes.get_hard_ecb_oracle_prefix()
        assert aes.get_hard_ecb_oracle_prefix() is not None

    def test_hard_ecb_get_num_prefix_bytes(self):
        block_len = 16
        key = aes.get_rand_aes_key(block_len)

        pre = 14
        def oracle(x): return aes.aes_ecb_encrypt(utils.pkcs7_pad(bytearray(b'\xee') * pre + x, block_len), key)

        diff_block_index = 0
        assert aes.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 2

        pre = 6
        assert aes.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 10

        diff_block_index = 1
        pre = 20
        assert aes.get_num_prefix_bytes(diff_block_index, block_len, oracle) == 12

    def test_hard_ecb_diff_block_index(self):
        block_len = 16
        key = aes.get_rand_aes_key(block_len)

        pre = 4

        def oracle(x): return aes.aes_ecb_encrypt(utils.pkcs7_pad(bytearray(b'\x01') * pre + x, block_len), key)

        assert aes.get_diff_block_index(block_len, oracle) == 0

        pre = 20
        assert aes.get_diff_block_index(block_len, oracle) == 1

        pre = 16
        assert aes.get_diff_block_index(block_len, oracle) == 1

    def test_detect_oracle_block_size(self):
        block_size = 16

        actual = aes.detect_ecb_oracle_block_size(aes.simple_ecb_oracle)
        assert actual == block_size

        actual = aes.detect_ecb_oracle_block_size(aes.hard_ecb_oracle)
        assert actual == block_size

    def test_ecb_oracle_encryption_mode(self):
        key = aes.get_rand_aes_key(16)
        pt = bytearray("A", "utf-8") * 256
        expected = aes.Mode.ECB

        actual = aes.detect_aes_encryption_mode(aes.simple_ecb_oracle(pt), len(key))
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
