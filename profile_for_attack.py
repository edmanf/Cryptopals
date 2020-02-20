from KVParser import KVParser
import aes
import utils


def profile_attack():
    key = aes.get_rand_aes_key(16)

    base = KVParser.profile_for(bytearray()).encrypt(key)
    min_length = len(base)

    block_size = 0
    for i in range(1, 512):
        junk_bytes = bytearray("A", "utf-8") * i
        length = len(KVParser.profile_for(junk_bytes).encrypt(key))
        if length > min_length:
            block_size = length - min_length
            break
    num_pre_bytes = block_size - len("email=")
    pre_bytes = bytearray("A", "utf-8") * num_pre_bytes  # aligns payload
    payload = utils.pkcs7_pad(bytearray("admin", "utf-8"), block_size)
    post_bytes = bytearray("B", "utf-8") * (len("user") - 1)  # room for &

    input = pre_bytes + payload + post_bytes

    ct = bytearray(KVParser.profile_for(input).encrypt(key))
    test = KVParser.decrypt_profile(ct, key)
    ct_payload = ct[block_size:2 * block_size]
    result = ct[:-1 * block_size] + ct_payload

    return KVParser.decrypt_profile(result, key)


if __name__ == '__main__':
    profile = profile_attack()
    print(profile.to_string())
