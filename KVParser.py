import utils
import aes


class KVParser:
    def __init__(self, args, encoding="utf-8"):
        self.args = {}
        self.encoding = encoding

        for arg in args.split(bytes("&", encoding)):
            key, value = arg.split(bytes("=", encoding))
            self.args[bytes(key)] = value

    def get(self, key):
        return self.args[key]

    def get_repr(self):
        result = bytearray()
        for key in self.args:
            result += key + \
                      bytes("=", self.encoding) + \
                      self.args[bytes(key)] + \
                      bytes("&", self.encoding)
        return result[:-1]  # removes fencepost &

    def to_string(self):
        return self.get_repr().decode()

    def encrypt(self, aes_key):
        """ Returns an aes encrypyted string of this KVParser.
        Decrypting with the given key and passing the decrypted string
        to the KVParser constructor will rebuild the parser. """
        padded = utils.pkcs7_pad(
            bytearray(self.to_string(), self.encoding),
            len(aes_key))
        return aes.aes_ecb_encrypt(padded, aes_key)

    @classmethod
    def decrypt_profile(cls, ciphertext, aes_key):
        """ Decrypts the ciphertext with aes_key and returns a KVParser
        built with the resulting plaintext. """

        # Need to remove potential padding from plaintext
        plaintext = aes.aes_ecb_decrypt(ciphertext, aes_key)

        block_size = len(aes_key)
        # remove padding
        for i in range(block_size):
            index = len(plaintext) - 1 - i
            if utils.is_byte_letter(plaintext[index]):
                return KVParser(plaintext[:index + 1])
        return KVParser(plaintext)

    @classmethod
    def profile_for(cls, email_address, encoding="utf-8"):
        """ Creates a parser for the user profile with the given
        email_address. email_address must be a string. """
        sanitized = KVParser.sanitize_email(email_address)
        uid = bytes("10", encoding)
        role = (bytes("user", encoding))

        args = bytearray("email=", encoding) + \
            sanitized + \
            bytes("&uid=", encoding) + \
            uid + \
            bytes("&role=", encoding) + \
            role

        return KVParser(args)

    @classmethod
    def sanitize_email(cls, email_address, encoding="utf-8"):
        """ Returns the email address with "=" and "&" characters
        removed. """
        result = bytearray()
        for c in email_address:
            if c is not ord("=") and c is not ord("&"):
                result.append(c)

        return result
