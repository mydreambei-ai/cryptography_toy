import random

import numpy as np
from sympy import Integer, Mod, Poly, div, isprime, primefactors, symbols


def legendre_symbol(a, p):
    a = a % p
    symbol = pow(a, (p - 1) // 2, p)
    if symbol == p - 1:
        return -1
    return symbol


def cipolla(a, p):
    if legendre_symbol(a, p) != 1:
        return None

    if a == 0:
        return 0

    class ComplexMod:
        def __init__(self, re, im, mod):
            self.re = re % mod
            self.im = im % mod
            self.mod = mod

        def __mul__(self, other):
            re = (self.re * other.re + self.im * other.im * w) % self.mod
            im = (self.re * other.im + self.im * other.re) % self.mod
            return ComplexMod(re, im, self.mod)

    b = 0
    while legendre_symbol(b * b - a, p) != -1:
        b += 1
    w = b * b - a

    x = ComplexMod(b, 1, p)
    res = ComplexMod(1, 0, p)
    n = (p + 1) // 2

    while n:
        if n % 2:
            res = res * x
        x = x * x
        n //= 2
    return res.re


def int_to_bytes(n: int) -> bytes:
    import math

    return n.to_bytes(math.ceil(n.bit_length() / 8), "little")


def bytes_to_int(s: bytes) -> int:
    return int.from_bytes(s, "little")


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def find_primitive_root(n):
    if n == 1:
        return 1
    if not isprime(n):
        raise ValueError(f"{n} 不是素数，因此没有原根。")

    factors = primefactors(n - 1)

    for g in range(2, n):
        if all(pow(g, (n - 1) // factor, n) != 1 for factor in factors):
            return g
    return None


def miller_rabin_prime_test(n, k=5):
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

    # 进行 k 次测试
    for _ in range(k):
        a = random.randint(2, n - 2)
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


def generate_prime(n) -> int:
    p = None
    while 1:
        if miller_rabin_prime_test(n):
            p = n
            break
        n -= 1
    return p


def fast_convolution(a, b):
    # 计算两个向量长度之和减一
    n = len(a) + len(b) - 1

    # 计算FFT，零填充到n长度
    A = np.fft.fft(a, n)
    B = np.fft.fft(b, n)

    # 频域逐元素相乘
    C = A * B

    # 逆FFT转换回时域
    result = np.fft.ifft(C)

    # 返回结果取实数部分
    return np.real(result)


def convolution_via_matrix(a, b):
    n = len(a)
    m = len(b)

    # 构建 Toeplitz 矩阵
    conv_matrix = np.zeros((n + m - 1, m))
    for i in range(n):
        conv_matrix[i : i + m, i] = b

    # 矩阵乘法
    result = np.dot(conv_matrix, a)

    return result


def fast_circular_convolution(a, b):
    # 假设a和b长度相同，且为n

    # 计算FFT
    A = np.fft.fft(a)
    B = np.fft.fft(b)

    # 频域逐元素相乘
    C = A * B

    # 逆FFT转换回时域
    result = np.fft.ifft(C)

    # 返回结果取实数部分
    return np.real(result)


def polynomial_inverse_mod(f, mod_poly, m):
    """
    使用扩展欧几里得算法在模m的多项式环中计算多项式的逆元。

    参数:
    f: 多项式f的系数列表（从低次到高次）
    mod_poly: 模多项式的系数列表（从低次到高次）
    m: 模数

    返回:
    逆元多项式的系数列表
    """
    x = symbols("x")

    # 定义多项式
    f = Poly(f, x, domain="ZZ")
    mod_poly = Poly(mod_poly, x, domain="ZZ")

    # 扩展欧几里得算法
    def extended_gcd(a, b):
        if b == 0:
            return (a, Poly(1, x), Poly(0, x))  # GCD, u, v
        gcd_poly, u1, v1 = extended_gcd(b, Mod(a, b))
        u = v1
        v = u1 - div(a, b)[0] * v1
        return (gcd_poly, u, v)

    # 计算扩展欧几里得算法
    gcd_poly, u, _ = extended_gcd(f, mod_poly)

    # 检查是否可逆
    if not gcd_poly.is_one:
        raise ValueError("多项式在给定的模下没有逆元。")

    # 归一化结果
    inverse_poly = Mod(u, mod_poly)

    # 模数运算，确保系数在 [0, m-1] 范围内
    inverse_coeffs = [Integer(coef % m) for coef in inverse_poly.all_coeffs()]
    return inverse_coeffs
