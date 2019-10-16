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
        actual = utils.PKCS7_pad(message, pad_length)
        assert actual.decode() == expected
        
        message = bytearray("YELLOW SUBMARINE", "utf-8")
        pad_length = 16
        expected = "YELLOW SUBMARINE"
        actual = utils.PKCS7_pad(message, pad_length)
        assert actual.decode() == expected
        
        message = bytearray("HELLO WORLD", "utf-8")
        pad_length = 16
        expected = "HELLO WORLD\x05\x05\x05\x05\x05"
        actual = utils.PKCS7_pad(message, pad_length)
        assert actual.decode() == expected
        
    def test_c10(self):
        """ Implement CBC mode. """
        input_file = "res/10.txt"
        expected_file = "res/10_expected.txt"
        
        f = open(expected_file)
        expected = f.read()
        f.close()
        
        f = open(input_file)
        b64_text = f.read()
        f.close()
        
        input = convert.b64_string_to_bytes(b64_text)
        key = bytearray("YELLOW SUBMARINE", "utf-8")
        iv = bytes("\x00", "ascii") * len(key)
        actual = aes.aes_cbc_decrypt(input, key, iv)
        assert actual.decode() == expected
        
        
    def test_c11(self):
        """ An ECB/CBC detection oracle. """
        plaintext = bytearray("A", "utf-8") * 256
        result = aes.ecb_cbc_encryption_oracle(plaintext, 
            mode = aes.Mode.ECB)
        mode = aes.detect_aes_encryption_mode(result.ciphertext, 16)
        assert mode == aes.Mode.ECB
        
        result = aes.ecb_cbc_encryption_oracle(plaintext, 
            mode = aes.Mode.CBC)
        mode = aes.detect_aes_encryption_mode(result.ciphertext, 16) 
        assert mode == aes.Mode.CBC
        
    def test_c12(self):
        """ Byte-at-a-time ECB decryption (Simple) """
        expected = aes.get_unknown_string_c12().decode()
        
        assert aes.simple_ecb_oracle_decryption().decode() == expected
        
    def test_c13(self):
        assert pfa.profile_attack()["role"] == admin
        
        
class TestMisc:
    def test_detect_oracle_block_size(self):
        key_len = 16
        key = aes.get_rand_aes_key(key_len)
        
        actual = aes.detect_ecb_oracle_block_size(key)
        assert actual == key_len
        
        key_len = 32
        key = aes.get_rand_aes_key(key_len)
        
        actual = aes.detect_ecb_oracle_block_size(key)
        assert actual == key_len
        
    def test_ecb_oracle_encryption_mode(self):
        key = aes.get_rand_aes_key(16)
        pt = bytearray("A", "utf-8") * 256
        expected = aes.Mode.ECB
        
        actual = aes.detect_aes_encryption_mode(aes.simple_ecb_oracle(pt, key), len(key))
        assert actual == expected
        
    def test_kvparser(self):
        args = bytearray("foo=HELLO&bar=WORLD", "utf-8")
        assert KVParser(args).get_repr() == args
        
        args = bytearray("foo=HELLO", "utf-8")
        assert KVParser(args).get_repr() == args
        
    def test_profile_for(self):
        input = bytearray("foo@bar.com", "utf-8")
        expected = "email=foo@bar.com&uid=10&role=user"
        assert KVParser.profile_for(input).to_string() == expected
        
    def test_email_sanitizer(self):
        input = bytearray("foo@bar.com&role=admin", "utf-8")
        expected_sanitize = bytearray("foo@bar.comroleadmin", "utf-8")
        assert KVParser.sanitize_email(input) == expected_sanitize
    
        expected = bytearray(
            "email=foo@bar.comroleadmin&uid=10&role=user", 
            "utf-8")
        assert KVParser.profile_for(input).to_string() == expected.decode()
        
    def test_KVParser_enc_dec(self):
        input = bytearray("foo@bar.com", "utf-8")
        expected = "email=foo@bar.com&uid=10&role=user"
        key = bytearray("YELLOW SUBMARINE", "utf-8")
        
        ct = KVParser.profile_for(input).encrypt(key)
        parser = KVParser.decrypt_profile(ct, key)
        assert parser.to_string() == expected
        
        input = bytearray("foo@bar.com&role=admin", "utf-8")
        expected = "email=foo@bar.comroleadmin&uid=10&role=user"
        ct = KVParser.profile_for(input).encrypt(key)
        parser = KVParser.decrypt_profile(ct, key)
        assert parser.to_string() == expected
        
        
        
