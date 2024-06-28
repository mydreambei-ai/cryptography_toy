from rsa  import generate_keys
from galois import GF, GFItem
"""
Homomorphic Encryption:
Encrypt(X+Y) == Encrypt(X) + Encrypt(Y)
Homo_encrypt(F(x,y)) = F(Homo_encrypt(x), Homo_encrypt(y))
"""

def F(x,y)->GFItem:
    return x*y

def homo_encrypt(m, pk)->GFItem:
    d, n = pk
    o = pow(m, d, n)
    return GF(n)(o)

def decrypt(m:GFItem, sk):
    e, n = sk
    m = m.item
    return pow(m, e, n)


if __name__ == "__main__":

    sk, pk = generate_keys(2**64)
    m = homo_encrypt(F(6, 7), pk)
    print(f"homo_encrypt: {m}")
    m1 = F(homo_encrypt(6, pk), homo_encrypt(7, pk))
    print(f"encrypt: {m1}")
    m = decrypt(m1, sk)
    print(f"decrypt: {m}")
