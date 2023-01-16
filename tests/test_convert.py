import unittest

from src.cryptopals import convert

class TestConvert(unittest.TestCase):
    def test_hex_string_to_bytes(self):
        hex_string = "deadbeef"
        expected = b"\xde\xad\xbe\xef"
        bytes_output = convert.hex_string_to_bytes(hex_string)
        self.assertEqual(bytes_output, expected)

if __name__ == "__main__":
    unittest.main()