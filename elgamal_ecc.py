from hash_elliptic_curve import point_to_message, message_to_point
from curves import Ed25519_G, Ed25519, point_compress, point_decompress
import random


def generate_keys():
    p = Ed25519.p
    sk = random.randint(2, p - 1)
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
    return point_compress(a) + point_compress(b)


def decrypt(m: bytes, sk):
    a = point_decompress(m[:32])
    b = point_decompress(m[32:])
    print(f"a: {a}")
    print(f"b: {b}")
    mp = Ed25519.sub_point(a, Ed25519.mul_point(b, sk))
    print(f"decrypt message point: {mp}")
    m1 = point_to_message(mp)
    return m1


if __name__ == "__main__":
    message = b"Hello, worldddhsofsfhof"
    sk, pk = generate_keys()

    encrypt_m = encrypt(message, pk)
    print(f"encrypt_m: {len(encrypt_m)},{encrypt_m}")
    print(decrypt(encrypt_m, sk))
    print(message)
