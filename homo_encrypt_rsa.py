from galois import GF, GFItem
from rsa import generate_keys

"""
Homomorphic Encryption:
Encrypt(X+Y) == Encrypt(X) + Encrypt(Y)
Homo_encrypt(F(x,y)) = F(Homo_encrypt(x), Homo_encrypt(y))
"""


def F_mul(x, y) -> GFItem:
    return x * y


def F_div(x, y) -> GFItem:
    xy = x / y
    if isinstance(xy, float):
        return int(xy)
    return xy


def homo_encrypt(m, pk) -> GFItem:
    d, n = pk
    o = pow(m, d, n)
    return GF(n)(o)


def decrypt(m: GFItem, sk):
    e, n = sk
    m = m.item
    return pow(m, e, n)


def homo_mul(x, y, sk, pk):
    m = homo_encrypt(F_mul(x, y), pk)
    print(f"homo_encrypt: {m}")
    m1 = F_mul(homo_encrypt(x, pk), homo_encrypt(y, pk))
    print(f"encrypt: {m1}")
    m = decrypt(m1, sk)
    print(f"decrypt: {m}")


def homo_div(x, y, sk, pk):
    m = homo_encrypt(F_div(x, y), pk)
    print(f"homo_encrypt: {m}")
    m1 = F_div(homo_encrypt(x, pk), homo_encrypt(y, pk))
    print(f"encrypt: {m1}")
    m = decrypt(m1, sk)
    print(f"decrypt: {m}")


if __name__ == "__main__":
    sk, pk = generate_keys(2**64)
    homo_mul(6, 7, sk, pk)
    homo_div(8, 2, sk, pk)
