import io

import convert
import aes
import utils
import xor


class TestSet1:
    def test_c1(self):
        """ Convert hex to base64 """
        plain = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        actual = convert.hex_string_to_b64(plain).decode()

        assert actual == expected

    def test_c2(self):
        """ Fixed XOR """
        input1 = "1c0111001f010100061a024b53535009181c"
        input2 = "686974207468652062756c6c277320657965"
        expected = "746865206b696420646f6e277420706c6179"

        a = convert.hex_string_to_bytes(input1)
        b = convert.hex_string_to_bytes(input2)
        actual = xor.fixed_xor(a, b).hex()

        assert actual == expected

    def test_c3(self):
        """ Single-byte XOR cipher """
        input1 = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
        expected = "Cooking MC's like a pound of bacon"  # From solving the challenge

        a = convert.hex_string_to_bytes(input1)
        actual = xor.single_byte_xor(a).message
        assert actual.decode() == expected

    def test_c4(self):
        """ Detect single-character XOR """
        input1 = "4.txt"
        expected = "Now that the party is jumping\n"

        f = utils.res_file_open(input1)
        lines = [convert.hex_string_to_bytes(x.strip('\n')) for x in list(f)]
        f.close()
        actual = xor.detect_single_character_xor(lines).message
        assert actual.decode() == expected

    def test_c5(self):
        """ Implement repeating-key XOR """
        input_file = "5_input.txt"
        expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527" \
                   "2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
        key = "ICE"

        f = utils.res_file_open(input_file)
        plaintext = bytearray(f.read(), "utf-8")
        f.close()
        actual = xor.repeating_key_xor(plaintext, bytearray(key, "utf-8"))

        assert actual == convert.hex_string_to_bytes(expected)

    def test_c6(self):
        """ Break repeating-key XOR """
        input_file = "6.txt"
        expected_file = "6_expected.txt"

        f = utils.res_file_open(expected_file)
        expected = f.read()
        f.close()

        f = utils.res_file_open(input_file)
        b64_text = f.read()
        f.close()

        input_text = convert.b64_string_to_bytes(b64_text)
        actual = xor.decrypt_repeating_key_xor(input_text)

        assert (actual.decode() == expected)

    def test_c7(self):
        """ AES in ECB mode """
        key = "YELLOW SUBMARINE"
        input_file = "7.txt"
        expected_file = "7_expected.txt"

        f = utils.res_file_open(input_file)
        b64_text = f.read()
        f.close()

        ciphertext = convert.b64_string_to_bytes(b64_text)

        f = utils.res_file_open(expected_file)
        expected = f.read()
        f.close()

        actual = aes.aes_ecb_decrypt(ciphertext, bytearray(key, "utf-8"))

        assert actual.decode() == expected  # actual currently leaves 4 EOT bytes

    def test_c8(self):
        """ Detect AES in ECB mode """
        input_file = "8.txt"
        expected_file = "8_expected.txt"
        key_size = 16

        f = utils.res_file_open(input_file)
        hex_strings = [x.rstrip('\n') for x in f.readlines()]
        f.close()
        input_string = [convert.hex_string_to_bytes(x) for x in hex_strings]

        f = utils.res_file_open(expected_file)
        expected = convert.hex_string_to_bytes(f.read())
        f.close()

        actual = aes.detect_aes_in_ecb_mode(input_string, key_size)

        assert actual == expected
