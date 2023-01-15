"""  This class contains methods for converting from one format to another """

import base64


def hex_string_to_bytes(hex_str):
    """ Convert the hex string to a bytes object and return it.
    
    Keyword arguments:
    hex_str -- a String object comprised of hexadecimal digits
    """

    return bytes.fromhex(hex_str)


def hex_to_b64(hex_bytes):
    """ Convert the hex  to base64 and return it.
    
    Keyword arguments:
    hex_bytes -- a bytes object
    """

    return base64.b64encode(hex_bytes)


def hex_string_to_b64(hex_str):
    """ Convert the hex string to a base64 encoded byte string and return it.
    
    Keyword arguements:
    hex_str -- a String of hexadecimal digits
    """

    return hex_to_b64(hex_string_to_bytes(hex_str))


def b64_string_to_bytes(b64_str):
    return hex_string_to_bytes(base64.b64decode(b64_str).hex())
