"""
密码学工具函数库

本模块提供了密码学中常用的数学工具函数，包括：
- 有限域上的算术运算（勒让德符号、Cipolla算法等）
- 素数生成和测试
- 多项式运算和卷积
- 字节与整数转换
- 扩展欧几里得算法等

这些函数被其他密码学实现所依赖。
"""

import random
import math
from typing import Optional, Tuple, List, Union, Any

import numpy as np
from sympy import Integer, Mod, Poly, div, isprime, primefactors, symbols


def legendre_symbol(a: int, p: int) -> int:
    """
    计算勒让德符号 (a/p)

    参数:
        a: 整数
        p: 奇素数

    返回:
        1: 如果a是p的二次剩余
        -1: 如果a是p的二次非剩余
        0: 如果a是p的倍数
    """
    if p <= 1 or p % 2 == 0:
        raise ValueError("p必须是奇素数")

    a = a % p
    if a == 0:
        return 0

    symbol = pow(a, (p - 1) // 2, p)
    if symbol == p - 1:
        return -1
    return symbol


def cipolla(a: int, p: int) -> Optional[int]:
    """
    Cipolla算法计算模p下的平方根

    计算x使得x^2 ≡ a (mod p)，其中p是奇素数

    参数:
        a: 需要求平方根的数
        p: 模数（奇素数）

    返回:
        x: 使得x^2 ≡ a (mod p)的解，若不存在则返回None
    """
    # 特殊情况处理
    a = a % p
    if a == 0:
        return 0  # 0的平方根是0

    # 检查a是否是p的二次剩余
    if legendre_symbol(a, p) != 1:
        return None

    # 定义复数模p域的类
    class ComplexMod:
        """有限域上的复数表示"""
        def __init__(self, re: int, im: int, mod: int):
            self.re = re % mod
            self.im = im % mod
            self.mod = mod

        def __mul__(self, other: 'ComplexMod') -> 'ComplexMod':
            """复数乘法，使用w作为虚部的平方"""
            re = (self.re * other.re + self.im * other.im * w) % self.mod
            im = (self.re * other.im + self.im * other.re) % self.mod
            return ComplexMod(re, im, self.mod)

        def __str__(self) -> str:
            return f"{self.re} + {self.im}i mod {self.mod}"

    # 寻找一个b使得b^2-a是p的二次非剩余
    b = 0
    while legendre_symbol((b * b - a) % p, p) != -1:
        b += 1

    # 定义全局变量w供ComplexMod类使用
    global w
    w = (b * b - a) % p  # w是p的二次非剩余

    # 使用快速幂计算(b+i)^((p+1)/2)
    x = ComplexMod(b, 1, p)  # b+i
    res = ComplexMod(1, 0, p)  # 1+0i
    n = (p + 1) // 2

    # 快速幂算法
    while n:
        if n % 2:
            res = res * x
        x = x * x
        n //= 2

    return res.re


def int_to_bytes(n: int, endian: str = "little") -> bytes:
    """
    将整数转换为字节串

    参数:
        n: 要转换的整数
        endian: 字节序，"little"或"big"

    返回:
        对应的字节串
    """
    if n < 0:
        raise ValueError("不支持负数转换为字节串")

    byte_length = max(1, math.ceil(n.bit_length() / 8))
    return n.to_bytes(byte_length, endian)


def bytes_to_int(s: bytes, endian: str = "little") -> int:
    """
    将字节串转换为整数

    参数:
        s: 要转换的字节串
        endian: 字节序，"little"或"big"

    返回:
        对应的整数
    """
    return int.from_bytes(s, endian)


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    扩展欧几里得算法，计算ax + by = gcd(a,b)的解

    参数:
        a, b: 输入整数

    返回:
        (gcd, x, y): 满足ax + by = gcd(a,b)的一组解
    """
    if a == 0:
        return b, 0, 1

    # 使用迭代方式而不是递归方式，避免大数溢出
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    # 此时 old_r 是 gcd, old_s 和 old_t 是贝祖系数
    return old_r, old_s, old_t


def find_primitive_root(n: int) -> Optional[int]:
    """
    寻找模n的原根

    参数:
        n: 模数，必须是素数

    返回:
        模n的一个原根，如果找不到则返回None

    抛出:
        ValueError: 如果n不是素数
    """
    if n == 1:
        return 1

    if not isprime(n):
        raise ValueError(f"{n} 不是素数，因此没有原根。")

    # 计算n-1的素因数
    factors = primefactors(n - 1)

    # 对于每个候选g，检查g^((n-1)/p) mod n != 1对所有素因数p成立
    for g in range(2, n):
        if all(pow(g, (n - 1) // factor, n) != 1 for factor in factors):
            return g

    return None


def miller_rabin_prime_test(n: int, k: int = 5) -> bool:
    """
    Miller-Rabin素性测试

    参数:
        n: 要测试的数
        k: 测试轮数，越大准确性越高

    返回:
        如果n可能是素数返回True，否则返回False
    """
    # 处理基本情况
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # 将 n-1 写成 2^r * d 的形式，其中 d 是奇数
    r, d = 0, n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    # 使用确定性测试基数（对较小的n）
    if n < 2048:
        # 对于小于2048的数，这些测试基数已被证明足够
        bases = [2] if n < 341550071728321 else [2, 3, 5, 7, 11, 13, 17]
        bases = [a for a in bases if a < n]
        test_rounds = min(k, len(bases))
        test_bases = bases[:test_rounds]
    else:
        # 对于更大的数，使用随机基数
        test_bases = [random.randint(2, n - 2) for _ in range(k)]

    # 进行Miller-Rabin测试
    for a in test_bases:
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int, safe: bool = False) -> int:
    """
    生成指定位数的素数

    参数:
        bits: 素数的位数
        safe: 如果为True，生成安全素数(p = 2q+1，q也是素数)

    返回:
        一个bits位的素数
    """
    if bits < 2:
        raise ValueError("位数必须至少为2")

    # 确保生成的数至少有bits位
    lower_bound = 1 << (bits - 1)
    upper_bound = (1 << bits) - 1

    max_attempts = 1000  # 设置最大尝试次数
    attempts = 0

    while attempts < max_attempts:
        # 生成随机奇数
        candidate = random.randint(lower_bound, upper_bound) | 1

        if safe:
            # 如果需要安全素数，检查(p-1)/2是否为素数
            q = (candidate - 1) // 2
            if miller_rabin_prime_test(candidate, k=10) and miller_rabin_prime_test(q, k=10):
                return candidate
        elif miller_rabin_prime_test(candidate, k=10):
            return candidate

        attempts += 1

    raise RuntimeError(f"无法在{max_attempts}次尝试内生成{bits}位素数")


def find_next_prime(n: int) -> int:
    """
    找到大于或等于n的下一个素数

    参数:
        n: 起始数

    返回:
        大于或等于n的下一个素数
    """
    if n <= 1:
        return 2

    # 如果n是偶数，增加到下一个奇数
    if n % 2 == 0:
        n += 1
    else:
        n += 2

    # 寻找下一个素数
    while not miller_rabin_prime_test(n):
        n += 2

    return n


def find_prev_prime(n: int) -> int:
    """
    找到小于或等于n的最大素数

    参数:
        n: 起始数

    返回:
        小于或等于n的最大素数
    """
    if n <= 2:
        return 2

    # 如果n是偶数，减少到前一个奇数
    if n % 2 == 0:
        n -= 1

    while n > 1 and not miller_rabin_prime_test(n):
        n -= 2

    return n if n > 1 else 2


def fast_convolution(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    使用FFT计算两个序列的快速卷积

    参数:
        a, b: 输入序列，NumPy数组

    返回:
        卷积结果
    """
    # 计算两个向量长度之和减一（卷积结果的长度）
    n = len(a) + len(b) - 1

    # 计算FFT，零填充到n长度
    A = np.fft.fft(a, n)
    B = np.fft.fft(b, n)

    # 频域逐元素相乘
    C = A * B

    # 逆FFT转换回时域
    result = np.fft.ifft(C)

    # 处理浮点数精度问题
    result_real = np.real(result)
    result_rounded = np.round(result_real)

    # 当实数部分接近整数时，返回整数结果
    epsilon = 1e-10
    if np.all(np.abs(result_real - result_rounded) < epsilon):
        return result_rounded.astype(int)

    # 返回结果取实数部分
    return result_real


def convolution_via_matrix(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    使用矩阵乘法计算卷积

    这种方法更适合小规模卷积，它构建一个 Toeplitz 矩阵并进行矩阵向量乘法

    参数:
        a, b: 输入序列

    返回:
        卷积结果
    """
    a = np.asarray(a)
    b = np.asarray(b)
    n = len(a)
    m = len(b)

    # 构建托普利兹矩阵
    result = np.zeros(n + m - 1)
    for i in range(n):
        for j in range(m):
            result[i + j] += a[i] * b[j]

    # 处理浮点数精度问题
    if np.issubdtype(a.dtype, np.integer) and np.issubdtype(b.dtype, np.integer):
        return np.round(result).astype(int)

    return result


def fast_circular_convolution(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    计算两个序列的循环卷积（假设序列长度相同）

    循环卷积适用于周期信号或环形数据结构

    参数:
        a, b: 输入序列，长度必须相同

    返回:
        循环卷积结果
    """
    a = np.asarray(a)
    b = np.asarray(b)

    if len(a) != len(b):
        raise ValueError("循环卷积要求两个输入序列长度相同")

    n = len(a)
    result = np.zeros(n)

    # 直接计算循环卷积
    for k in range(n):
        for i in range(n):
            j = (k - i) % n  # 循环索引
            result[k] += a[i] * b[j]

    # 处理精度问题
    result_rounded = np.round(result)

    # 当结果接近整数时，返回整数结果
    epsilon = 1e-10
    if np.all(np.abs(result - result_rounded) < epsilon):
        return result_rounded.astype(int)

    return result


def polynomial_inverse_mod(f: Union[List[int], np.ndarray],
                          mod_poly: Union[List[int], np.ndarray],
                          m: int) -> List[int]:
    """
    使用扩展欧几里得算法在模m的多项式环中计算多项式的逆元

    计算满足 f(x) * g(x) ≡ 1 (mod mod_poly(x), m) 的多项式g(x)

    参数:
        f: 多项式f的系数列表（从低次到高次）
        mod_poly: 模多项式的系数列表（从低次到高次）
        m: 整数模数

    返回:
        逆元多项式的系数列表

    抛出:
        ValueError: 如果多项式在给定模下不可逆
    """
    if m <= 1:
        raise ValueError("模数m必须大于1")

    # 创建符号变量
    x = symbols("x")

    # 将输入转换为SymPy多项式
    f = Poly(f, x, domain="ZZ")
    mod_poly = Poly(mod_poly, x, domain="ZZ")

    # 内部扩展欧几里得算法，用于多项式
    def extended_poly_gcd(a: Poly, b: Poly) -> Tuple[Poly, Poly, Poly]:
        """多项式扩展欧几里得算法"""
        if b == 0:
            return (a, Poly(1, x), Poly(0, x))  # (GCD, u, v)

        # 计算模多项式的结果
        gcd_poly, u1, v1 = extended_poly_gcd(b, Mod(a, b))

        # 计算贝祖系数
        quotient, _ = div(a, b)
        u = v1
        v = u1 - quotient * v1

        return (gcd_poly, u, v)

    try:
        # 计算多项式GCD及贝祖系数
        gcd_poly, u, _ = extended_poly_gcd(f, mod_poly)

        # 检查多项式是否可逆（GCD是否为1）
        if not gcd_poly.is_one:
            raise ValueError("多项式在给定的模下没有逆元，GCD不为1")

        # 将结果在模多项式下规范化
        inverse_poly = Mod(u, mod_poly)

        # 对系数取模，确保在[0, m-1]范围内
        inverse_coeffs = [Integer(coef % m) for coef in inverse_poly.all_coeffs()]

        # 返回正确的系数顺序（从低次到高次）
        return inverse_coeffs[::-1] if inverse_poly.degree() >= 0 else []
    except Exception as e:
        raise ValueError(f"计算多项式逆元时出错: {str(e)}")
