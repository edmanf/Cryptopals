import utils

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
        pad_byte = b'\x01'
        expected = "HELLO WORLD\x01\x01\x01\x01\x01"
        actual = utils.PKCS7_pad(message, pad_length, pad_byte)
        assert actual.decode() == expected