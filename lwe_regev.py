import numpy as np

# 参数设置
n = 5  # 安全参数
q = 23  # 模数
m = 10  # 矩阵 A 的行数
l = 3  # 要加密的比特数


# 离散高斯分布生成噪声函数
def discrete_gaussian(stddev, size):
    return np.random.normal(0, stddev, size).astype(int) % q


# 密钥生成
def keygen():
    A = np.random.randint(0, q, size=(m, n))  # 随机矩阵 A
    s = np.random.randint(0, q, size=n)  # 随机私钥向量 s
    e = discrete_gaussian(1, m)  # 噪声向量 e
    b = (A @ s + e) % q  # 公钥向量 b
    return (A, b), s  # 返回公钥 (A, b) 和私钥 s


# 加密多比特消息
def encrypt(pk, message_bits):
    A, b = pk
    l = len(message_bits)  # 要加密的比特数
    r = np.random.randint(0, 2, size=(m, l))  # 随机选择向量 r，大小为 (m, l)
    c1 = (A.T @ r) % q  # 计算密文 c1，大小为 (n, l)
    c2 = (b.T @ r + (q // 2) * message_bits) % q  # 计算密文 c2，大小为 (1, l)
    return c1, c2


# 解密多比特消息
def decrypt(sk, ciphertext):
    c1, c2 = ciphertext
    s = sk
    v = (c2 - c1.T @ s) % q  # 计算 v，大小为 (1, l)

    # 解密每个比特
    decrypted_bits = []
    for vi in v:
        # 解密时比较 v_i 与 q/4 和 3q/4 的大小
        if vi < q // 4 or vi > 3 * q // 4:
            decrypted_bits.append(0)
        else:
            decrypted_bits.append(1)

    return decrypted_bits


# 示例
if __name__ == "__main__":
    # 生成密钥对
    pk, sk = keygen()

    # 要加密的多比特消息
    message_bits = np.array([1, 0, 1])  # 3 比特的消息
    print(f"message: {message_bits}")
    # 加密消息
    ciphertext = encrypt(pk, message_bits)
    print(f"加密后的密文: {ciphertext}")

    # 解密密文
    decrypted_message = decrypt(sk, ciphertext)
    print(f"解密后的明文: {decrypted_message}")
