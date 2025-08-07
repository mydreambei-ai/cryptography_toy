import random

from common import (
    bytes_to_int,
    find_primitive_root,
    int_to_bytes,
    miller_rabin_prime_test,
)
from galois import GF, GFItem

"""
sk, (g, p, y=g^sk)

g: primitive_root of prime {p}

p: big prime

y = g^sk


encrypt
m: must be in {p} space
k: random number

a = g^k
b = y^k*m
return (a, b)

decrypt:
m = b/a^sk = b/(g^k)^sk = (g^sk)^k * m / (g^k)^sk = m

"""


def generate_keys(n):
    p = None
    while 1:
        if miller_rabin_prime_test(n):
            p = n
            break
        n -= 1

    g = find_primitive_root(p)

    sk = random.randint(2, p - 1)

    pk = (p, g, pow(g, sk, p))
    return sk, pk


def encrypt(m, pk):
    m = bytes_to_int(m)

    p, g, y = pk

    k = random.randint(2, p - 1)

    return (pow(g, k, p), pow(y, k, p) * m)


def decrypt(m, sk, pk):
    a, b = m
    p = pk[0]
    F = GF(p)
    m1: GFItem = F(b) / F(pow(a, sk, p))
    return int_to_bytes(m1.item)


if __name__ == "__main__":
    m = b"hello,world"

    sk, pk = generate_keys(2**256)
    m1 = encrypt(m, pk)
    m2 = decrypt(m1, sk, pk)
    print(m, m2)
