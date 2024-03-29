import unittest

import src.cryptopals.aes_key_schedule as aes_key_schedule

class TestAesKeySchedule(unittest.TestCase):
    def test_rot_word(self):
        word = b"\x01\x02\x03\x04"
        self.assertEqual(aes_key_schedule.rot_word(word), b"\x02\x03\x04\x01")
        
    def test_round_constant(self):
        for i in range(10):
            actual = aes_key_schedule.get_round_constant(i + 1)
            self.assertEqual(actual, aes_key_schedule.round_constants[i])
            
    def test_round_constant_bounds(self):
        with self.assertRaises(ValueError, msg = "Round constant index cannot be less than 1."):
            aes_key_schedule.get_round_constant(0)
        with self.assertRaises(ValueError, msg = "Round constant index cannot be greater than 10."):
            aes_key_schedule.get_round_constant(11)
            
    def test_sbox_cell(self):
        self.assertEqual(aes_key_schedule.get_sub_byte(b"\x9a"), b"\xb8")
        self.assertEqual(aes_key_schedule.get_sub_byte(b"\x00"), b"\x63")
        self.assertEqual(aes_key_schedule.get_sub_byte(b"\xff"), b"\x16")
        self.assertEqual(aes_key_schedule.get_sub_byte(b"\x5a"), b"\xbe")
        
    def test_inverse_sbox(self):
        self.assertEqual(aes_key_schedule.get_inverse_sub_byte(b"\xb8"), b"\x9a")
        self.assertEqual(aes_key_schedule.get_inverse_sub_byte(b"\x63"), b"\x00")
        self.assertEqual(aes_key_schedule.get_inverse_sub_byte(b"\x16"), b"\xff")
        self.assertEqual(aes_key_schedule.get_inverse_sub_byte(b"\xbe"), b"\x5a")
        
    def test_most_sig_nib(self):
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\x9a"), 9)
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\x00"), 0)
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\xff"), 15)
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\x5a"), 5)
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\xb8"), 11)
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\x63"), 6)
        self.assertEqual(aes_key_schedule.get_most_significant_nibble(b"\x16"), 1)
        
    
    def test_least_sig_nib(self):
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\x9a"), 10)
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\x00"), 0)
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\xff"), 15)
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\xb8"), 8)
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\x63"), 3)
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\x16"), 6)
        self.assertEqual(aes_key_schedule.get_least_significant_nibble(b"\xbe"), 14)
            
    def test_left_circular_bitshift(self):
        with self.assertRaises(ValueError, msg = "Argument must be a single byte."):
            aes_key_schedule.left_circular_bitshift(b"")
        with self.assertRaises(ValueError, msg = "Argument must be a single byte."):
            aes_key_schedule.left_circular_bitshift(b"\x0000")
            
        self.assertEqual(aes_key_schedule.left_circular_bitshift(b"\x00"), b"\x00")
        self.assertEqual(aes_key_schedule.left_circular_bitshift(b"\xff"), b"\xff")
        self.assertEqual(aes_key_schedule.left_circular_bitshift(b"\x01"), b"\x02")
        self.assertEqual(aes_key_schedule.left_circular_bitshift(b"\xaa"), b"\x55")
        self.assertEqual(aes_key_schedule.left_circular_bitshift(b"\x55"), b"\xaa")
        
    def test_get_most_significant_bit(self):
        self.assertEqual(aes_key_schedule.get_most_significant_bit(b"\x70"), 0)
        self.assertEqual(aes_key_schedule.get_most_significant_bit(b"\xf0"), 1)
        self.assertEqual(aes_key_schedule.get_most_significant_bit(b"\xff"), 1)
    
if __name__ == "__main__":
    unittest.main()