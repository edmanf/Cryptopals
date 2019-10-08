import io

import convert
import aes
import xor

class TestSet1:
    def test_c1_convert_hex_to_base64(self):
        input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        actual = convert.hex_string_to_b64(input).decode()
        
        assert actual == expected

    def test_c2_fixed_XOR(self):
        input1 = "1c0111001f010100061a024b53535009181c"
        input2 = "686974207468652062756c6c277320657965"
        expected = "746865206b696420646f6e277420706c6179"
        
        a = convert.hex_string_to_bytes(input1)
        b = convert.hex_string_to_bytes(input2)
        actual = xor.fixed_XOR(a, b).hex()
        
        assert actual == expected

    def test_c3_single_byte_XOR_cipher(self):
        input1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        expected = "Cooking MC's like a pound of bacon" # From solving the challenge
        
        a = convert.hex_string_to_bytes(input1)
        actual = xor.single_byte_XOR(a).message
        assert actual.decode() == expected

    def test_c4_detect_single_character_XOR(self):
        input1 = "res/4.txt"
        expected = "Now that the party is jumping\n"
        
        f = open(input1)
        lines = [convert.hex_string_to_bytes(x.strip('\n')) for x in list(f)]
        f.close()
        actual = xor.detect_single_character_XOR(lines).message
        assert actual.decode() == expected

    def test_c5_implement_repeating_key_XOR(self):
        input_file = "res/5_input.txt"
        expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        key = "ICE"
        
        f = open(input_file)
        plaintext = bytearray(f.read(), "utf-8")
        f.close()
        actual = xor.repeating_key_XOR(plaintext, bytearray(key, "utf-8"))

        assert actual == convert.hex_string_to_bytes(expected)
        
    def test_c6_break_repeating_key_XOR(self):
        input_file = "res/6.txt"
        expected_file = "res/6_expected.txt"
        
        f = open(expected_file)
        expected = f.read()
        f.close()
        
        f = open(input_file)
        b64_text = f.read()
        f.close()

        input = convert.b64_string_to_bytes(b64_text)
        actual = xor.decrypt_repeating_key_XOR(input)
        
        assert(actual.decode() == expected)
        
    def test_c7_AES_in_ECB_mode(self):
        key = "YELLOW SUBMARINE"
        input_file = "res/7.txt"
        expected_file = "res/7_expected.txt"
        
        f = open(input_file)
        b64_text = f.read()
        f.close()
        
        ciphertext = convert.b64_string_to_bytes(b64_text)
        
        f = open(expected_file)
        expected = f.read()
        f.close()
        
        actual = aes.aes_ecb_decrypt(ciphertext, bytearray(key, "utf-8"))
        
        assert actual.decode() == expected # actual currently leaves 4 EOT bytes
        
    def test_c8_detect_AES_in_ECB_mode(self):
        input_file = "res/8.txt"
        expected_file = "res/8_expected.txt"
        key_size = 16
        
        f = open(input_file)
        hex_strings = [x.rstrip('\n') for x in f.readlines()]
        f.close()
        input = [convert.hex_string_to_bytes(x) for x in hex_strings]
        
        f = open(expected_file)
        expected = convert.hex_string_to_bytes(f.read())
        f.close()
        
        actual = aes.detect_AES_ECB(input, key_size)
        
        assert actual == expected