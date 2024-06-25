from curves import Ed25519
from curves import Ed25519_G as G
from common import int_to_bytes, bytes_to_int
from elliptic_curve import Point
import random
import hashlib

"""

"""


def generate_key():
    sk = random.randint(2, Ed25519.order)
    pk = Ed25519.mul_point(G, sk)
    return sk, pk


def sha512(m):
    if isinstance(m, str):
        m = m.encode("utf8")
    return hashlib.sha512(m).digest()


def convert_point_bytes(p: Point):
    return int_to_bytes(p.x) + int_to_bytes(p.y)


def sign(m, sk, pk):
    h = sha512(m)
    h1 = h[:32]
    h2 = h[32:]
    r = bytes_to_int(sha512(h1 + m)) % Ed25519.order

    R = Ed25519.mul_point(G, r)

    s = (
        r
        + bytes_to_int(convert_point_bytes(R) + convert_point_bytes(pk) + m)
        * sk
        % Ed25519.order
    ) % Ed25519.order

    return R, s


def verify(pk, msg, R, s):
    S = (
        bytes_to_int(convert_point_bytes(R) + convert_point_bytes(pk) + msg)
        % Ed25519.order
    )

    return Ed25519.mul_point(G, s) == Ed25519.add_point(R, Ed25519.mul_point(pk, S))


if __name__ == "__main__":
    m = b"hello world"
    sk, pk = generate_key()

    R, s = sign(m, sk, pk)
    print(R, s)

    print(verify(pk, m, R, s))
