import random


def is_prime(p):
    if p < 2:
        return False
    if p == 2:
        return True
    if p % 2 == 0:
        return False
    for i in range(3, int(p**0.5) + 1, 2):
        if p % i == 0:
            return False
    return True


def get_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if p % 4 != 3:
            continue
        if is_prime(p):
            return p


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def generate_bbs_seed(n):
    while True:
        x = random.randrange(2, n)
        if gcd(x, n) == 1:
            return x


def bbs_keystream(n, seed, num_bits):
    x = seed
    stream = []
    for _ in range(num_bits):
        x = pow(x, 2, n)
        bit = x % 2  # 可扩展为多位输出
        stream.append(bit)
    return stream


def keystream_bytes(bbs_bits):
    # 将 bit 流打包成字节列表
    out = bytearray()
    for i in range(0, len(bbs_bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bbs_bits):
                byte = (byte << 1) | bbs_bits[i + j]
        out.append(byte)
    return bytes(out)


def xor_encrypt(message: bytes, keystream: bytes) -> bytes:
    return bytes([m ^ k for m, k in zip(message, keystream)])


# ==== DEMO ====
bits = 32  # 安全起见应选 >= 512，演示选小一些以加快计算
p = get_prime(bits)
q = get_prime(bits)
n = p * q
seed = generate_bbs_seed(n)

print(f"p = {p}\nq = {q}\nn = {n}\nseed = {seed}")

# 明文
plaintext = b"hello world!"

# 生成足够的比特
bit_len = len(plaintext) * 8
bbs_bits = bbs_keystream(n, seed, bit_len)
keystream = keystream_bytes(bbs_bits)

# 加密
ciphertext = xor_encrypt(plaintext, keystream)
print("Ciphertext (hex):", ciphertext.hex())

# 解密（用同样 keystream）
decrypted = xor_encrypt(ciphertext, keystream)
print("Decrypted:", decrypted)
