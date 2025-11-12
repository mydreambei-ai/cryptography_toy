import numpy as np


def logistic_sequence(x0, r, length):
    """生成 Logistic 混沌序列"""
    seq = np.zeros(length)
    x = x0
    for i in range(length):
        x = r * x * (1 - x)
        seq[i] = x
    return seq


def logistic_encrypt(data: bytes, x0: float, r: float):
    """
    Logistic 映射加密
    data: 明文（bytes）
    x0, r: 密钥参数
    """
    n = len(data)
    chaotic_seq = logistic_sequence(x0, r, n)
    key_stream = (chaotic_seq * 256).astype(np.uint8)
    cipher = bytes([d ^ k for d, k in zip(data, key_stream)])
    return cipher


def logistic_decrypt(cipher: bytes, x0: float, r: float):
    """
    Logistic 映射解密（同加密过程）
    """
    return logistic_encrypt(cipher, x0, r)  # 对称算法


if __name__ == "__main__":
    # 示例明文
    plaintext = b"Logistic map encryption demo!"
    print("原文:", plaintext)

    # 密钥参数（r 需在 (3.57, 4) 区间）
    x0 = 0.7123456789
    r = 3.987654321

    # 加密
    cipher = logistic_encrypt(plaintext, x0, r)
    print("密文:", cipher)

    # 解密
    decrypted = logistic_decrypt(cipher, x0, r)
    print("解密后:", decrypted)
