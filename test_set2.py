import utils
import convert
import aes

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
            mode = aes.ECBCBCOracleCipher.Mode.ECB)
        mode = aes.detect_ecb_cbc_encryption(result.ciphertext, 16)
        assert mode == aes.ECBCBCOracleCipher.Mode.ECB
        
        result = aes.ecb_cbc_encryption_oracle(plaintext, 
            mode = aes.ECBCBCOracleCipher.Mode.CBC)
        mode = aes.detect_ecb_cbc_encryption(result.ciphertext, 16) 
        assert mode == aes.ECBCBCOracleCipher.Mode.CBC
        
        
            
            
    
    
    