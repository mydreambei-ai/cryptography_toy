from common import miller_rabin_prime_test, int_to_bytes, bytes_to_int, extended_gcd

def generate_prime(n)->int:
    p = None
    while 1:
        if miller_rabin_prime_test(n):
            p = n
            break
        n -= 1
    return p

def generate_keys(n):
    p = generate_prime(n)
    q = generate_prime(n**2)
    print(f"p: {p}")
    print(f"q: {q}")
    n = p * q
    phi = (p-1) * (q-1)

    e = 65537
    d = extended_gcd(e, phi)[1]
    if d < 0:
        d = phi + d
    print(f"n:", n.bit_length())

    return (e, n), (d, n)

def encrypt(m, pk):
    d, n = pk
    m = bytes_to_int(m)
    return int_to_bytes(pow(m, d, n))


def decrypt(m, sk):
    m = bytes_to_int(m)
    e, n = sk
    return int_to_bytes(pow(m, e, n))


if __name__ == "__main__":
    m = b"hello worldssssss"

    sk, pk = generate_keys(2**64)
    m1 = encrypt(m, pk)
    m2 = decrypt(m1, sk)
    print(f"encrypt: {m1}")
    print(m2 == m)
