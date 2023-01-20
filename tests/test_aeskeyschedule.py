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
            
if __name__ == "__main__":
    unittest.main()