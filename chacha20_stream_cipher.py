import struct

# --- 工具函数 ---


def rotl32(x, n):
    """循环左移 32-bit"""
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def quarter_round(state, a, b, c, d):
    """核心 ARX Quarter Round 操作"""
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_init_state(key, counter, nonce):
    """初始化 16×32bit 状态矩阵"""
    assert len(key) == 32
    assert len(nonce) == 12

    constants = b"expand 32-byte k"
    return (
        list(struct.unpack("<4I", constants))
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce))
    )


def chacha20_block(key, counter, nonce):
    """生成一个 64 字节 keystream block"""
    state = chacha20_init_state(key, counter, nonce)
    working = state.copy()

    for _ in range(10):  # 20轮变换
        # Column round
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)
        # Diagonal round
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    output = [(x + y) & 0xFFFFFFFF for x, y in zip(state, working)]
    return struct.pack("<16I", *output)  # 64 字节 keystream block


def chacha20_encrypt(key, nonce, plaintext, counter=1):
    """流加密：明文 ⊕ keystream"""
    assert len(key) == 32
    assert len(nonce) == 12

    ciphertext = b""
    for block_index in range((len(plaintext) + 63) // 64):
        keystream = chacha20_block(key, counter + block_index, nonce)
        block = plaintext[block_index * 64 : (block_index + 1) * 64]
        ciphertext += bytes([a ^ b for a, b in zip(block, keystream[: len(block)])])
    return ciphertext


if __name__ == "__main__":
    key = bytes(range(32))  # 256-bit 密钥
    nonce = b"123456789012"  # 96-bit nonce
    message = b"ChaCha20 stream cipher demo, secure and fast!"  # 明文

    ciphertext = chacha20_encrypt(key, nonce, message)
    decrypted = chacha20_encrypt(key, nonce, ciphertext)  # 再加密一次即解密

    print("密文 (hex):", ciphertext.hex())
    print("解密后:", decrypted.decode())
