from rsa  import generate_keys
from galois import GF, GFItem
from elgamal_dh import generate_keys
import random
"""
Homomorphic Encryption:
Encrypt(X+Y) == Encrypt(X) + Encrypt(Y)
Homo_encrypt(F(x,y)) = F(Homo_encrypt(x), Homo_encrypt(y))
"""

def F_add(x,y)->GFItem:
    return x+y

def F_sub(x, y)->GFItem:
    xy = x - y
    return xy

def homo_encrypt(m, pk)->GFItem:
    pass

def decrypt(m:GFItem, sk):
    pass

def homo_mul(x,y, sk, pk):
    pass

def homo_div(x,y, sk, pk):
    pass

if __name__ == "__main__":

    sk, pk = generate_keys(2**64)
    homo_mul(6,7, sk, pk)
    homo_div(8,2, sk, pk)
