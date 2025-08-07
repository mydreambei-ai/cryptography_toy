"""
椭圆曲线密钥交换 (ECDH) 示例

ECDH (Elliptic Curve Diffie-Hellman) 是基于椭圆曲线密码学的密钥交换协议。
它允许两方在不安全的通道上建立共享的密钥。

本示例演示了如何使用标准椭圆曲线进行 ECDH 密钥交换。
"""

import hashlib
import secrets
from typing import Optional, Tuple

from elliptic_curve import Point
from standard_curves import StandardCurve, get_curve


class ECDHExchange:
    """ECDH 密钥交换实现"""

    def __init__(self, curve_name: str = 'secp256k1'):
        """
        初始化 ECDH 交换

        参数:
            curve_name: 使用的椭圆曲线名称，默认为 secp256k1
        """
        self.curve_info: StandardCurve = get_curve(curve_name)
        self.curve = self.curve_info.curve
        self.G = self.curve_info.G

        # 私钥和公钥初始化为 None
        self.private_key: Optional[int] = None
        self.public_key: Optional[Point] = None

    def generate_keypair(self) -> Tuple[int, Point]:
        """
        生成 ECDH 密钥对

        返回:
            (私钥, 公钥) 元组
        """
        # 生成随机私钥 (1 <= d < n)
        private_key = secrets.randbelow(self.curve_info.n - 1) + 1

        # 计算公钥 Q = d*G
        public_key = self.curve.mul_point(self.G, private_key)

        # 保存密钥对
        self.private_key = private_key
        self.public_key = public_key

        return private_key, public_key

    def compute_shared_secret(self, other_public_key: Point) -> bytes:
        """
        计算共享密钥

        参数:
            other_public_key: 对方的公钥

        返回:
            共享密钥的哈希值（32字节）

        抛出:
            ValueError: 如果私钥未设置或公钥无效
        """
        if self.private_key is None:
            raise ValueError("必须先生成或设置私钥")

        # 验证对方的公钥在曲线上
        if other_public_key not in self.curve:
            raise ValueError("无效的公钥点，不在指定的椭圆曲线上")

        # 计算共享点 S = d_A * Q_B = d_A * d_B * G = d_B * Q_A
        shared_point = self.curve.mul_point(other_public_key, self.private_key)

        # 使用点的 x 坐标作为共享密钥的种子
        x_bytes = shared_point.x.to_bytes((shared_point.x.bit_length() + 7) // 8, byteorder='big')

        # 使用 SHA-256 哈希 x 坐标生成最终的共享密钥
        shared_secret = hashlib.sha256(x_bytes).digest()

        return shared_secret

    def set_private_key(self, private_key: int) -> None:
        """
        设置私钥并计算对应的公钥

        参数:
            private_key: 私钥值

        抛出:
            ValueError: 如果私钥无效
        """
        if not 1 <= private_key < self.curve_info.n:
            raise ValueError("私钥必须在范围 [1, n-1] 内")

        self.private_key = private_key
        self.public_key = self.curve.mul_point(self.G, private_key)


def demo_ecdh():
    """ECDH 密钥交换演示"""
    print("=== 椭圆曲线密钥交换 (ECDH) 演示 ===")

    # 创建 Alice 和 Bob 的 ECDH 实例
    curve_name = 'secp256k1'  # 使用比特币的曲线
    print(f"\n使用椭圆曲线: {curve_name}")

    alice = ECDHExchange(curve_name)
    bob = ECDHExchange(curve_name)

    # 生成密钥对
    alice_private, alice_public = alice.generate_keypair()
    bob_private, bob_public = bob.generate_keypair()

    print(f"\nAlice 的私钥: {alice_private}")
    print(f"Alice 的公钥: {alice_public}")
    print(f"\nBob 的私钥: {bob_private}")
    print(f"Bob 的公钥: {bob_public}")

    # 计算共享密钥
    alice_shared = alice.compute_shared_secret(bob_public)
    bob_shared = bob.compute_shared_secret(alice_public)

    # 验证共享密钥相同
    print(f"\nAlice 的共享密钥: {alice_shared.hex()}")
    print(f"Bob 的共享密钥: {bob_shared.hex()}")
    print(f"\n共享密钥相同: {alice_shared == bob_shared}")

    # 演示使用不同曲线
    print("\n\n使用 NIST P-256 曲线:")
    alice_p256 = ECDHExchange('P-256')
    bob_p256 = ECDHExchange('P-256')

    # 生成密钥对
    alice_p256.generate_keypair()
    bob_p256.generate_keypair()

    # 计算共享密钥
    alice_p256_shared = alice_p256.compute_shared_secret(bob_p256.public_key)
    bob_p256_shared = bob_p256.compute_shared_secret(alice_p256.public_key)

    print(f"NIST P-256 共享密钥相同: {alice_p256_shared == bob_p256_shared}")


if __name__ == "__main__":
    demo_ecdh()
