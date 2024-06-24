
from common import generate_prime, find_primitive_root
import random
from elliptic_curve import EllipticCurve

def native_dh_exchange(p, g):
    a = random.randint(2, p-1)

    b = random.randint(2, p-1)

    pa = pow(g, a, p)

    pb = pow(g, b, p)


    print(f"pa: {pa}")
    print(f"pb: {pb}")

    pab = pow(pa, b, p)
    pba = pow(pb, a, p)
    print(f"pab: {pab}")
    print(f"pba: {pba}")
    print(f"pab == pba", pab==pba)

def elliptic_curve_dh_exchange(E: EllipticCurve, g):
    a = random.randint(2, E.order)
    b = random.randint(2, E.order)

    ga = E.mul_point(g, a)
    gb = E.mul_point(g, b)
    print("ga", ga)
    print("gb", gb)

    gab = E.mul_point(ga, b)
    gba = E.mul_point(gb, a)

    print("gab", gab)
    print("gba", gba)
    print("gab == gba", gab==gba)


if __name__ == "__main__":
    p = generate_prime(2**16)
    g = find_primitive_root(p)
    native_dh_exchange(p, g)

    E = EllipticCurve(2,3, p=431, order=440)
    g = E(142, 154)
    elliptic_curve_dh_exchange(E, g)
