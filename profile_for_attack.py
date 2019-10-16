from KVParser import KVParser
import aes
import utils

def profile_attack():
    key = aes.get_rand_aes_key(16)
    

    base = KVParser.profile_for("")
    min_length = len(base.to_string())
    
    num_pre_bytes = 0
    block_size = 0
    for i in range(1, 512):
        length = len(KVParser.profile_for("A" * i).encrypt(key))
        if length > min_length:
            num_pre_bytes = length
            block_size = length - min_length
            break
    pre_bytes = bytearray("A", "utf-8") * (block_size - len("email="))      
    payload = utils.PKCS7_pad(bytearray("admin", "utf-8"), block_size)
    post_bytes = bytearray("A", "utf-8") * (len("user"))
    
    input = pre_bytes + payload + post_bytes
    
    ct = bytearray(KVParser.profile_for(input.decode()).encrypt(key))
    ct[block_size * -1:] = payload
    
    return KVParser.decrypt_profile(ct, key)
    
    
    
    # input = X random junk bytes + ("admin" + padding)
    
    # insert 3 more bytes because you want "user" in its own block
    # one from 
    
    # input = X + ("admin" + padding) + Y
    
    # replace last block of ct with the ("admin" + padding) block
    
if __name__ == '__main__':
    print(profile_attack().to_string())