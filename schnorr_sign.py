"""
Schnorr 签名算法实现

Schnorr 签名是一种数字签名算法，基于离散对数问题的困难性。
相比传统的 DSA/ECDSA 签名，Schnorr 签名具有以下优势：
1. 更简洁的数学结构
2. 可证明的安全性（在随机预言机模型下）
3. 支持多签名聚合（signature aggregation）
4. 线性化的签名验证

本实现使用大素数有限域上的离散对数问题
"""

import hashlib
import secrets
from typing import Tuple, Optional


class SchnorrSignature:
    """Schnorr 签名实现类"""

    # 算法参数
    # 使用一个安全的大素数 p，其中 p-1 有一个大素数因子 q
    # p = 2^256 - 2^32 - 977（与比特币使用的相同）
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    # 基本上所有密码学应用都选择 q = (p-1)/2
    q = (p - 1) // 2
    # 选择一个生成元 g，其阶为 q
    g = 2

    @staticmethod
    def keygen() -> Tuple[int, int]:
        """
        生成 Schnorr 密钥对

        返回:
            Tuple[int, int]: (私钥, 公钥)
        """
        # 生成随机私钥 (1 <= sk <= q-1)
        sk = secrets.randbelow(SchnorrSignature.q - 1) + 1
        # 计算公钥 pk = g^sk mod p
        pk = pow(SchnorrSignature.g, sk, SchnorrSignature.p)
        return sk, pk

    @staticmethod
    def hash_to_int(data: bytes) -> int:
        """
        哈希函数，将数据哈希为一个整数

        参数:
            data: 待哈希的字节数据

        返回:
            int: 哈希值（整数形式，在群的阶范围内）
        """
        h = hashlib.sha256(data).digest()
        return int.from_bytes(h, byteorder='big') % SchnorrSignature.q

    @staticmethod
    def sign(sk: int, message: bytes, k: Optional[int] = None) -> Tuple[int, int]:
        """
        生成 Schnorr 签名

        参数:
            sk: 私钥 (1 <= sk <= q-1)
            message: 待签名消息
            k: 可选的随机数，如果不提供则安全生成

        返回:
            Tuple[int, int]: 签名对 (r, s)

        安全注意:
            - 对于同一消息，每次签名必须使用不同的 k
            - k 必须保密，泄露会导致私钥被破解
        """
        if not (1 <= sk < SchnorrSignature.q):
            raise ValueError("无效的私钥")

        # 如果没有提供 k，则安全生成一个随机 k
        if k is None:
            k = secrets.randbelow(SchnorrSignature.q - 1) + 1
        elif not (1 <= k < SchnorrSignature.q):
            raise ValueError("无效的随机数 k")

        # 1. 计算 R = g^k mod p
        r = pow(SchnorrSignature.g, k, SchnorrSignature.p)

        # 2. 计算挑战值 e = H(R || m)
        # 将 r 转换为字节
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
        e = SchnorrSignature.hash_to_int(r_bytes + message)

        # 3. 计算 s = k + e*sk mod q
        s = (k + e * sk) % SchnorrSignature.q

        return r, s

    @staticmethod
    def verify(pk: int, message: bytes, signature: Tuple[int, int]) -> bool:
        """
        验证 Schnorr 签名

        参数:
            pk: 公钥
            message: 已签名消息
            signature: 签名对 (r, s)

        返回:
            bool: 如果签名有效则为 True，否则为 False
        """
        # 解包签名
        r, s = signature

        # 基本验证检查
        if not (1 <= r < SchnorrSignature.p and 1 <= s < SchnorrSignature.q):
            return False

        # 1. 计算挑战值 e = H(R || m)
        r_bytes = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
        e = SchnorrSignature.hash_to_int(r_bytes + message)

        # 2. 验证 g^s ?= R * pk^e mod p
        # 左侧: g^s mod p
        left = pow(SchnorrSignature.g, s, SchnorrSignature.p)

        # 右侧: R * pk^e mod p
        pk_e = pow(pk, e, SchnorrSignature.p)
        right = (r * pk_e) % SchnorrSignature.p

        # 验证等式是否成立
        return left == right


def demo():
    """演示 Schnorr 签名的使用"""
    print("=== Schnorr 签名演示 ===\n")

    # 1. 生成密钥对
    print("生成密钥对...")
    sk, pk = SchnorrSignature.keygen()
    print(f"私钥: {sk}")
    print(f"公钥: {pk}\n")

    # 2. 签名消息
    message = b"Hello, Schnorr Signature!"
    print(f"待签名消息: {message.decode()}")

    r, s = SchnorrSignature.sign(sk, message)
    print(f"签名 (r, s): ({r}, {s})\n")

    # 3. 验证签名
    valid = SchnorrSignature.verify(pk, message, (r, s))
    print(f"签名验证结果: {valid}")

    # 4. 验证被篡改的消息
    tampered_message = b"Hello, Tampered Message!"
    print(f"\n篡改后的消息: {tampered_message.decode()}")
    tampered_valid = SchnorrSignature.verify(pk, tampered_message, (r, s))
    print(f"篡改消息验证结果: {tampered_valid}")


if __name__ == "__main__":
    demo()
