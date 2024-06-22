
from math import gcd
from sympy import isprime, primefactors

import random

def int_to_bytes(n: int)->bytes:
    import math

    return n.to_bytes(math.ceil(n.bit_length()/8), "little")

def bytes_to_int(s: bytes)->int:
    return int.from_bytes(s, "little")

def find_primitive_root(n):
    if n == 1:
        return 1
    if not isprime(n):
        raise ValueError(f"{n} 不是素数，因此没有原根。")


    factors = primefactors(n - 1)

    for g in range(2, n):
        if all(pow(g,  (n-1)//factor, n) != 1 for factor in factors):
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
