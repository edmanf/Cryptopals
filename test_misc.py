import utils
import crypt

class TestMisc:
    def test_AES_ECB(self):
        message = bytearray("THE QUICK BROWN FOX", "utf-8")
        message = utils.PKCS7_pad(message, 16)
        key = bytearray("YELLOW SUBMARINE", "utf-8")
        
        ciphertext = crypt.aes_ecb_encrypt(message, key)
        plaintext = crypt.aes_ecb_decrypt(ciphertext, key)
        assert plaintext == message
    
    def test_hamming_distance(self):
        a = "this is a test"
        b = "wokka wokka!!!"
        expected = 37
        
        actual = utils.get_hamming_distance(
            bytes(a, "utf-8"), bytes(b, "utf-8"))
        assert actual == expected
        
    def test_transpose(self):
        blocks = [
            bytearray("HELL", "utf-8"),
            bytearray("OWOR", "utf-8"),
            bytearray("LDFO", "utf-8"),
            bytearray("OBAR", "utf-8"),
            bytearray("BAZ", "utf-8")]
        
        expected = [
            bytearray("HOLOB", "utf-8"),
            bytearray("EWDBA", "utf-8"),
            bytearray("LOFAZ", "utf-8"),
            bytearray("LROR", "utf-8")]   
        actual = utils.transpose(blocks)
        assert actual == expected
        
        blocks = [
            bytearray("HEL", "utf-8"),
            bytearray("LOW", "utf-8"),
            bytearray("ORL", "utf-8"),
            bytearray("DFO", "utf-8"),
            bytearray("OBA", "utf-8"),
            bytearray("RBA", "utf-8"),
            bytearray("Z", "utf-8")]
            
        expected = [
            bytearray("HLODORZ", "utf-8"),
            bytearray("EORFBB", "utf-8"),
            bytearray("LWLOAA", "utf-8")]
        actual = utils.transpose(blocks)
        assert actual == expected
        
    def test_make_blocks(self):
        a = bytearray("HELLOWORLDFOOBARBAZ", "utf-8")
        key_size = 4
        expected = [
            bytearray("HELL", "utf-8"),
            bytearray("OWOR", "utf-8"),
            bytearray("LDFO", "utf-8"),
            bytearray("OBAR", "utf-8")]
            
        assert utils.make_blocks(a, key_size) == expected
        
        key_size = 3
        expected = [
            bytearray("HEL", "utf-8"),
            bytearray("LOW", "utf-8"),
            bytearray("ORL", "utf-8"),
            bytearray("DFO", "utf-8"),
            bytearray("OBA", "utf-8"),
            bytearray("RBA", "utf-8")]
        assert utils.make_blocks(a, key_size) == expected