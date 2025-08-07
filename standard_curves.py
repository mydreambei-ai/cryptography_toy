"""
常用椭圆曲线参数定义

本模块提供了密码学中常用的标准椭圆曲线参数。
包括 NIST 曲线、Brainpool 曲线、secp 曲线以及用于比特币的 secp256k1 等。

每个曲线定义包含以下参数：
- p: 有限域的模数（素数）
- a, b: 曲线参数，表示 y^2 = x^3 + ax + b
- Gx, Gy: 基点 G 的坐标
- n: 基点 G 的阶（子群的阶）
- h: 余因子（椭圆曲线群的阶除以 n）

参考资料:
- SEC 2: Recommended Elliptic Curve Domain Parameters
- FIPS PUB 186-4: Digital Signature Standard (DSS)
- RFC 5639: ECC Brainpool Standard Curves & Curve Generation
"""

from typing import Dict, Any, Optional, Tuple, Union
import sympy
from elliptic_curve import EllipticCurve, Point


class StandardCurve:
    """标准椭圆曲线参数的容器类"""

    def __init__(self, name: str, params: Dict[str, Any]):
        """
        初始化标准椭圆曲线

        参数:
            name: 曲线名称
            params: 曲线参数字典，包含 p, a, b, Gx, Gy, n, h
        """
        self.name = name
        self.params = params
        self.p = params['p']
        self.a = params['a']
        self.b = params['b']
        self.Gx = params['Gx']
        self.Gy = params['Gy']
        self.n = params['n']
        self.h = params['h']

        # 延迟初始化，仅在需要时创建
        self._curve = None
        self._G = None

    @property
    def curve(self) -> EllipticCurve:
        """获取椭圆曲线对象"""
        if self._curve is None:
            # 标准曲线的参数已经过验证，跳过素性检查
            self._curve = EllipticCurve(
                self.a, self.b, self.p, self.n,
                skip_primality_check=True
            )
        return self._curve

    @property
    def G(self) -> Point:
        """获取曲线的基点 G"""
        if self._G is None:
            self._G = self.curve(self.Gx, self.Gy)
        return self._G

    def __repr__(self) -> str:
        """返回曲线的字符串表示"""
        return f"StandardCurve({self.name})"

    def __str__(self) -> str:
        """返回曲线的详细字符串表示"""
        return (f"StandardCurve {self.name}:\n"
                f"  p = {self.p}\n"
                f"  a = {self.a}\n"
                f"  b = {self.b}\n"
                f"  G = ({self.Gx}, {self.Gy})\n"
                f"  n = {self.n}\n"
                f"  h = {self.h}")


# NIST 推荐曲线
# 参数来源: FIPS PUB 186-4

# P-192 (NIST P-192, secp192r1)
P192 = StandardCurve('P-192', {
    'p': 0xfffffffffffffffffffffffffffffffeffffffffffffffff,
    'a': 0xfffffffffffffffffffffffffffffffefffffffffffffffc,
    'b': 0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1,
    'Gx': 0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012,
    'Gy': 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811,
    'n': 0xffffffffffffffffffffffff99def836146bc9b1b4d22831,
    'h': 1
})

# P-224 (NIST P-224, secp224r1)
P224 = StandardCurve('P-224', {
    'p': 0xffffffffffffffffffffffffffffffff000000000000000000000001,
    'a': 0xfffffffffffffffffffffffffffffffefffffffffffffffffffffffe,
    'b': 0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4,
    'Gx': 0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21,
    'Gy': 0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34,
    'n': 0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d,
    'h': 1
})

# P-256 (NIST P-256, secp256r1)
P256 = StandardCurve('P-256', {
    'p': 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
    'a': 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc,
    'b': 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    'Gx': 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    'Gy': 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    'n': 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    'h': 1
})

# P-384 (NIST P-384, secp384r1)
P384 = StandardCurve('P-384', {
    'p': 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
    'a': 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc,
    'b': 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    'Gx': 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    'Gy': 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
    'n': 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    'h': 1
})

# P-521 (NIST P-521, secp521r1)
P521 = StandardCurve('P-521', {
    'p': 0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff,
    'a': 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc,
    'b': 0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
    'Gx': 0x0c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
    'Gy': 0x11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
    'n': 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
    'h': 1
})

# secp256k1 (用于比特币的曲线)
SECP256K1 = StandardCurve('secp256k1', {
    'p': 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    'a': 0,
    'b': 7,
    'Gx': 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    'Gy': 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
    'n': 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    'h': 1
})

# Brainpool 标准曲线
# 参数来源: RFC 5639

# brainpoolP256r1
BP256R1 = StandardCurve('brainpoolP256r1', {
    'p': 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377,
    'a': 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9,
    'b': 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6,
    'Gx': 0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262,
    'Gy': 0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997,
    'n': 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7,
    'h': 1
})

# brainpoolP384r1
BP384R1 = StandardCurve('brainpoolP384r1', {
    'p': 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53,
    'a': 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826,
    'b': 0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11,
    'Gx': 0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e,
    'Gy': 0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315,
    'n': 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565,
    'h': 1
})

# 曲线字典，用于通过名称查找曲线
CURVES = {
    'P-192': P192,
    'P-224': P224,
    'P-256': P256,
    'P-384': P384,
    'P-521': P521,
    'secp256k1': SECP256K1,
    'brainpoolP256r1': BP256R1,
    'brainpoolP384r1': BP384R1,
    # 别名
    'NIST P-192': P192,
    'NIST P-224': P224,
    'NIST P-256': P256,
    'NIST P-384': P384,
    'NIST P-521': P521,
    'secp192r1': P192,
    'secp224r1': P224,
    'secp256r1': P256,
    'secp384r1': P384,
    'secp521r1': P521,
}


def get_curve(name: str) -> StandardCurve:
    """
    通过名称获取标准曲线

    参数:
        name: 曲线名称

    返回:
        StandardCurve 对象

    抛出:
        ValueError: 如果找不到指定名称的曲线
    """
    if name not in CURVES:
        valid_names = ", ".join(sorted(set(CURVES.keys())))
        raise ValueError(f"未知的曲线名称: {name}。有效的曲线名称: {valid_names}")
    return CURVES[name]


def list_curves() -> None:
    """打印所有可用的标准曲线"""
    print("可用的标准椭圆曲线:")

    # 移除别名，只显示主要名称
    main_curves = {
        'P-192', 'P-224', 'P-256', 'P-384', 'P-521',
        'secp256k1', 'brainpoolP256r1', 'brainpoolP384r1'
    }

    for name in sorted(main_curves):
        curve = CURVES[name]
        bits = curve.p.bit_length()
        print(f"- {name}: {bits}位曲线")


def demo_standard_curves() -> None:
    """演示标准椭圆曲线的使用"""
    print("=== 标准椭圆曲线演示 ===\n")

    # 显示可用曲线
    list_curves()

    # 使用 secp256k1（比特币使用的曲线）
    print("\n使用 secp256k1 曲线（比特币使用的曲线）:")
    curve = get_curve('secp256k1')
    print(curve)

    # 获取曲线对象和基点
    ec = curve.curve
    G = curve.G

    # 计算 2G 和 3G
    G2 = ec.double_point(G)
    G3 = ec.add_point(G, G2)

    print(f"\n基点 G = {G}")
    print(f"[2]G = {G2}")
    print(f"[3]G = {G3}")

    # 验证点在曲线上
    print(f"\n验证 G 在曲线上: {G in ec}")
    print(f"验证 [2]G 在曲线上: {G2 in ec}")

    # 验证 n*G = O（无穷远点）
    # 使用小的倍数进行演示，避免大数计算
    small_mul = 10
    G10 = ec.mul_point(G, small_mul)
    print(f"\n计算 [{small_mul}]G = {G10}")

    # 验证 G 的阶是 n（这里只打印信息，不实际计算 n*G，因为 n 太大）
    print(f"基点 G 的阶为: {curve.n}")

    # 显示 P-256 曲线信息
    print("\n使用 NIST P-256 曲线:")
    p256 = get_curve('P-256')
    print(p256)


if __name__ == "__main__":
    demo_standard_curves()
