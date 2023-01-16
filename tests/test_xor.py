import unittest

from src.cryptopals import xor

class TestXor(unittest.TestCase):
    def test_unequal_fixed_xor(self):
        with self.assertRaises(ValueError, msg = "Lengths must be equal."):
            xor.fixed_length_xor(bytearray(), b"1")
            
    def test_fixed_length_xor(self):
        self.assertEqual(xor.fixed_length_xor(b"\xFF", b"\xFF"), b"\x00")
        self.assertEqual(xor.fixed_length_xor(b"\xFF", b"\x00"), b"\xFF")
        self.assertEqual(xor.fixed_length_xor(b"\x00", b"\xFF"), b"\xFF")
        self.assertEqual(xor.fixed_length_xor(b"\x00", b"\x00"), b"\x00")
        self.assertEqual(xor.fixed_length_xor(b"\x0F\xAA", b"\xAA\xAA"), b"\xA5\x00")