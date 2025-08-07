"""
Blum-Blum-Shub (BBS) 伪随机数生成器与流密码实现

BBS是一个密码学安全的伪随机数生成器，基于二次剩余理论。
它使用形式为 x_{n+1} = x_n^2 mod M 的递推关系，其中M是两个大素数的乘积。

安全特性：
1. 在合理参数选择下，BBS生成器被认为是密码学安全的
2. 其安全性基于整数分解问题的困难性
3. 通过了下一比特不可预测性测试

作者: [您的名字]
版本: 1.0
"""

import secrets
import math
from typing import Tuple, List, Optional, Dict, Any


def is_prime(p: int, num_trials: int = 5) -> bool:
    """
    使用Miller-Rabin素性测试确定一个数是否为素数

    Args:
        p: 要测试的数
        num_trials: 测试次数（越高越可靠）

    Returns:
        如果可能是素数返回True，否则返回False
    """
    if p < 2:
        return False
    if p == 2 or p == 3:
        return True
    if p % 2 == 0:
        return False

    # 将p-1写成d * 2^r的形式
    r, d = 0, p - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # 进行Miller-Rabin测试
    for _ in range(num_trials):
        a = secrets.randbelow(p - 3) + 2
        x = pow(a, d, p)
        if x == 1 or x == p - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, p)
            if x == p - 1:
                break
        else:
            return False
    return True


def get_blum_prime(bits: int) -> int:
    """
    生成一个形如4k+3的大素数（Blum素数）

    Args:
        bits: 素数的位数

    Returns:
        一个bits位的Blum素数

    注意:
        对于BBS，素数需要满足p ≡ 3 (mod 4)
    """
    if bits < 8:
        raise ValueError("位数太小，不安全（应至少为512位）")

    while True:
        # 确保生成的素数足够大且为4k+3形式
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 3
        # 确保p % 4 == 3
        if p % 4 != 3:
            p = p - (p % 4) + 3
        # 使用更严格的素性测试
        if is_prime(p, num_trials=10):
            return p


def gcd(a: int, b: int) -> int:
    """
    计算两个数的最大公约数

    Args:
        a, b: 要计算GCD的两个整数

    Returns:
        a和b的最大公约数
    """
    while b:
        a, b = b, a % b
    return a


def lcm(a: int, b: int) -> int:
    """
    计算两个数的最小公倍数

    Args:
        a, b: 要计算LCM的两个整数

    Returns:
        a和b的最小公倍数
    """
    return a * b // gcd(a, b)


def mod_inverse(a: int, m: int) -> int:
    """
    计算a在模m下的乘法逆元

    Args:
        a: 要求逆元的数
        m: 模数

    Returns:
        a在模m下的乘法逆元

    Raises:
        ValueError: 如果逆元不存在
    """
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a}在模{m}下没有乘法逆元")
    else:
        return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    扩展欧几里得算法，计算ax + by = gcd(a,b)的解

    Args:
        a, b: 输入整数

    Returns:
        (gcd, x, y): 满足ax + by = gcd(a,b)的一组解
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)


class BBSParameters:
    """存储BBS生成器参数的类"""

    def __init__(self, p: int, q: int, seed: int):
        """
        初始化BBS参数

        Args:
            p, q: 两个Blum素数
            seed: 初始种子
        """
        self.p = p
        self.q = q
        self.n = p * q
        self.seed = seed

        # 计算BBS周期（理论上的）
        self.lambda_n = lcm(p - 1, q - 1) // 4

    def to_dict(self) -> Dict[str, Any]:
        """将参数转换为字典用于存储"""
        return {
            "p": self.p,
            "q": self.q,
            "n": self.n,
            "seed": self.seed,
            "lambda_n": self.lambda_n
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BBSParameters':
        """从字典重建参数"""
        params = cls(data["p"], data["q"], data["seed"])
        params.lambda_n = data["lambda_n"]
        return params


def generate_bbs_parameters(bits: int = 512) -> BBSParameters:
    """
    生成BBS生成器所需的全部参数

    Args:
        bits: 每个素数的位数

    Returns:
        包含所有BBS参数的对象
    """
    # 生成两个Blum素数
    p = get_blum_prime(bits)
    q = get_blum_prime(bits)

    # 确保p和q不同
    while p == q:
        q = get_blum_prime(bits)

    # 计算模数n = p*q
    n = p * q

    # 生成种子
    seed = generate_bbs_seed(n)

    return BBSParameters(p, q, seed)


def generate_bbs_seed(n: int) -> int:
    """
    生成BBS的种子，必须与n互素

    Args:
        n: 模数

    Returns:
        一个与n互素的随机数作为种子
    """
    phi_n = (n - 1) // 4  # 粗略估计phi(n)的下界

    while True:
        # 使用加密安全的随机数生成器
        x = secrets.randbelow(n - 3) + 2
        if gcd(x, n) == 1:
            # 通过平方使种子成为二次剩余
            return pow(x, 2, n)


class BBSGenerator:
    """BBS伪随机数生成器的实现类"""

    def __init__(self, params: BBSParameters):
        """
        初始化BBS生成器

        Args:
            params: BBS参数
        """
        self.params = params
        self.state = params.seed
        self.counter = 0

    def reset(self):
        """重置生成器到初始状态"""
        self.state = self.params.seed
        self.counter = 0

    def next_bit(self) -> int:
        """
        生成下一个随机比特

        Returns:
            0或1的随机比特
        """
        self.state = pow(self.state, 2, self.params.n)
        self.counter += 1
        return self.state & 1  # 取最低位

    def next_bits(self, num_bits: int) -> List[int]:
        """
        生成指定数量的随机比特

        Args:
            num_bits: 要生成的比特数

        Returns:
            一个包含随机比特的列表
        """
        return [self.next_bit() for _ in range(num_bits)]

    def next_byte(self) -> int:
        """
        生成一个随机字节(8比特)

        Returns:
            一个0-255之间的随机整数
        """
        byte = 0
        for _ in range(8):
            byte = (byte << 1) | self.next_bit()
        return byte

    def next_bytes(self, num_bytes: int) -> bytes:
        """
        生成指定数量的随机字节

        Args:
            num_bytes: 要生成的字节数

        Returns:
            一个包含随机字节的bytes对象
        """
        return bytes(self.next_byte() for _ in range(num_bytes))


class BBSStreamCipher:
    """使用BBS生成器的流密码实现"""

    def __init__(self, params: Optional[BBSParameters] = None, bits: int = 512):
        """
        初始化流密码

        Args:
            params: BBS参数，如果不提供则自动生成
            bits: 当需要自动生成参数时，素数的位数
        """
        self.params = params if params else generate_bbs_parameters(bits)
        self.generator = BBSGenerator(self.params)

    def reset(self):
        """重置加密器状态"""
        self.generator.reset()

    def encrypt(self, plaintext: bytes) -> bytes:
        """
        加密数据

        Args:
            plaintext: 要加密的数据

        Returns:
            加密后的数据
        """
        # 生成等长的密钥流
        keystream = self.generator.next_bytes(len(plaintext))
        # 使用XOR操作加密
        return self._xor_bytes(plaintext, keystream)

    def decrypt(self, ciphertext: bytes) -> bytes:
        """
        解密数据

        Args:
            ciphertext: 要解密的数据

        Returns:
            解密后的数据
        """
        # 由于XOR的特性，解密操作与加密相同
        return self.encrypt(ciphertext)

    @staticmethod
    def _xor_bytes(data: bytes, keystream: bytes) -> bytes:
        """
        将数据与密钥流进行XOR操作

        Args:
            data: 输入数据
            keystream: 密钥流

        Returns:
            XOR操作后的数据
        """
        if len(data) != len(keystream):
            raise ValueError("数据长度与密钥流长度必须相同")
        return bytes(d ^ k for d, k in zip(data, keystream))

    def get_parameters(self) -> BBSParameters:
        """获取当前使用的参数"""
        return self.params


def run_security_check(bits: int = 512) -> Dict[str, Any]:
    """
    运行一系列安全性检查

    Args:
        bits: 素数位数

    Returns:
        包含安全评估结果的字典
    """
    results = {}

    # 创建参数和生成器
    params = generate_bbs_parameters(bits)
    generator = BBSGenerator(params)

    # 1. 计算理论周期
    results["theoretical_period"] = params.lambda_n

    # 2. 运行统计测试(简化版)
    num_samples = 10000
    bits = generator.next_bits(num_samples)
    ones_count = sum(bits)
    results["ones_percentage"] = ones_count / num_samples * 100

    # 3. 评估序列预测难度
    results["factorization_difficulty"] = f"约 2^{int(math.log2(params.n))} 操作"

    return results


if __name__ == "__main__":
    print("=" * 50)
    print("BBS流密码演示")
    print("=" * 50)

    # 为了演示目的，使用较小的位数
    demo_bits = 64  # 生产环境应至少使用1024位
    print(f"\n[注意] 本演示使用 {demo_bits} 位素数用于快速演示")
    print("       生产环境应使用至少1024位以确保安全性\n")

    # 创建流密码对象
    cipher = BBSStreamCipher(bits=demo_bits)
    params = cipher.get_parameters()

    # 显示参数
    print("生成的参数:")
    print(f"p = {params.p} ({params.p.bit_length()} bits)")
    print(f"q = {params.q} ({params.q.bit_length()} bits)")
    print(f"n = p*q = {params.n} ({params.n.bit_length()} bits)")
    print(f"seed = {params.seed}")

    # 演示加密解密
    plaintext = b"Hello, BBS stream cipher with improved security!"
    print(f"\n明文: {plaintext.decode()}")

    # 加密
    ciphertext = cipher.encrypt(plaintext)
    print(f"密文 (hex): {ciphertext.hex()}")

    # 重置生成器后解密
    cipher.reset()
    decrypted = cipher.decrypt(ciphertext)
    print(f"解密后: {decrypted.decode()}")

    # 验证
    assert decrypted == plaintext, "解密失败！"
    print("\n验证: 解密成功 ✓")

    # 安全评估
    print("\n" + "=" * 50)
    print("安全性评估 (简化版)")
    print("=" * 50)

    # 注意：完整安全评估应在合适参数下运行
    security = run_security_check(bits=demo_bits)
    print(f"理论周期长度: {security['theoretical_period']}")
    print(f"比特1出现频率: {security['ones_percentage']:.2f}% (理想: 50%)")
    print(f"分解模数所需计算复杂度: {security['factorization_difficulty']}")

    print("\n" + "=" * 50)
    print("使用建议:")
    print("1. 生产环境使用至少1024位素数")
    print("2. 每次加密会话生成新的参数")
    print("3. 妥善保管种子，泄露将导致所有消息可被解密")
    print("4. 考虑结合其他加密机制，如消息认证码提高安全性")
    print("=" * 50)
