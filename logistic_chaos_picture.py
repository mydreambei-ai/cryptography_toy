import numpy as np
from PIL import Image


# -----------------------------
# Logistic map sequence generator
# -----------------------------
def logistic_map_sequence(length, r=3.99, x0=0.5):
    seq = np.zeros(length, dtype=np.uint8)
    x = x0
    for i in range(length):
        x = r * x * (1 - x)
        seq[i] = int((x * 1e14) % 256)  # 放大以增加熵
    return seq


def chebyshev_map(n, k=39.4444, x0=0.7):
    """
    x0: 初始值, -1 <= x0 <= 1
    k: 映射参数
    n: 生成序列长度
    """
    seq = np.zeros(n, dtype=np.uint8)
    x = np.float64(x0)

    for i in range(n):
        x = np.cos(k * np.arccos(x))
        seq[i] = np.floor(np.float64(x + 1) * 1e5 % 256)
    return seq


def xorshift32(n, seed=123):
    seq = np.zeros(n, dtype=np.uint8)
    x = seed
    for i in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        seq[i] = x % 256
    return seq


# -----------------------------
# Encrypt/Decrypt function
# -----------------------------
def logistic_encrypt_decrypt(image_path, output_path, seq_generator):
    img = Image.open(image_path).convert("RGB")
    img_array = np.array(img, dtype=np.uint8)
    flat = img_array.flatten()

    seq = seq_generator(len(flat))
    # XOR
    encrypted = np.bitwise_xor(flat, seq)
    encrypted_img = encrypted.reshape(img_array.shape)

    # 使用无损格式保存
    Image.fromarray(encrypted_img).save(output_path, format="PNG")
    print(f"✅ Saved to {output_path}")
