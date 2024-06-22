import random
import hashlib
from common import int_to_bytes, bytes_to_int

p = 2**256-2**32-977
g = 2

sk = random.randint(1, p-1)
pk = pow(g, sk, p)


def H(msg):
    return int(hashlib.sha256(msg).hexdigest(), 16)

def schnorr_sign(sk, msg):
    k = random.randint(1, p-1)
    r = pow(g, k, p)
    e = H(int(r).to_bytes(32, "little") + msg)
    print(f"sign e: {e}")
    s = (k - sk * e) % (p-1)  # 注意这里的 (p-1)
    return (r, s)

def schnorr_verify(pk, msg, r, s):
    e = H(int(r).to_bytes(32, "little") + msg)
    print(f"verify e: {e}")
    return r == ( pow(g, s, p) * pow(pk, e, p)) % p




if __name__ == "__main__":
    msg = b"Hello, SageMath with Schnorr Signature!"
    r, s = schnorr_sign(sk, msg)
    print("签名 (r, s):", (r, s))
    valid = schnorr_verify(pk, msg, r, s)
    print(f"valid: {valid}")
