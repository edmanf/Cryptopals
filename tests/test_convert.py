import unittest

from src.cryptopals import convert

class TestConvert(unittest.TestCase):

    def setUp(self):
        self.hex_string = "deadbeef"
        self.hex_bytes = b"\xde\xad\xbe\xef"
        self.b64 = b"3q2+7w=="
        
    
    def test_hex_string_to_bytes(self):
        expected = self.hex_bytes
        actual = convert.hex_string_to_bytes(self.hex_string)
        self.assertEqual(actual, expected)
        
    def test_hex_to_base64(self):
        expected = self.b64
        actual = convert.hex_to_b64(self.hex_bytes)
        self.assertEqual(actual, expected)
        
    def test_hex_string_to_b64(self):
        expected = self.b64
        actual = convert.hex_string_to_b64(self.hex_string)
        self.assertEqual(actual, expected)
        
    def test_b64_string_to_hex(self):
        expected = self.hex_bytes
        actual = convert.b64_string_to_bytes("3q2+7w==")
        self.assertEqual(actual, expected)

if __name__ == "__main__":
    unittest.main()