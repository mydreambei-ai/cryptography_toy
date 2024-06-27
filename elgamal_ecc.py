from hash_elliptic_curve import point_to_message, message_to_point
from curves import Ed25519_G, Ed25519
import random

def generate_keys():
    p = Ed25519.p
    sk = random.randint(2, p-1)
    pk = Ed25519.mul_point(Ed25519_G, sk)
    return sk, pk

def encrypt(m, pk):
    m = message_to_point(m)
    print(f"message_to_point: {m}")
    p = Ed25519.p
    k = random.randint(2, p - 1)
    b = Ed25519.mul_point(Ed25519_G, k)
    a = Ed25519.add_point(Ed25519.mul_point(pk, k), m)

    print(f"a: {a}")
    print(f"b: {b}")
    return a,b

def decrypt(m, sk):
    a, b = m

    print(f"a: {a}")
    print(f"b: {b}")
    p = Ed25519.p
    mp = Ed25519.sub_point(a,  Ed25519.mul_point(b, sk))
    print(f"decrypt message point: {mp}")
    m1 = point_to_message(mp)
    return m1

if __name__ == "__main__":
    message = b"Hello, world"
    sk, pk = generate_keys()

    encrypt_m = encrypt(message, pk)

    print(decrypt(encrypt_m, sk))
