def F(right, key):
    return (right ^ key) & 0xFFFFFFFF


def feistel_encrypt_block(block, round_keys):
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF

    for key in round_keys:
        f_out = F(right, key)
        left, right = right, left ^ f_out

    # 注意：Feistel 网络中，加密结束后是 (R, L)
    return (right << 32) | left


def feistel_decrypt_block(block, round_keys):
    right = (block >> 32) & 0xFFFFFFFF
    left = block & 0xFFFFFFFF

    for key in reversed(round_keys):
        f_out = F(left, key)
        right, left = left, right ^ f_out

    return (left << 32) | right


if __name__ == "__main__":
    plaintext = 0x0123456789ABCDEF
    round_keys = [0x0F1571C9, 0x47D9E859, 0x0CB7ADD6, 0xAF7F6798]

    ciphertext = feistel_encrypt_block(plaintext, round_keys)
    decrypted = feistel_decrypt_block(ciphertext, round_keys)

    print("Plaintext:  ", hex(plaintext))
    print("Ciphertext: ", hex(ciphertext))
    print("Decrypted:  ", hex(decrypted))
