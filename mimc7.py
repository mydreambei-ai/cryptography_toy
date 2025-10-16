from hashlib import sha256

# MiMC hash (illustrative, ZK-friendly) implementation in Python
# https://iden3-docs.readthedocs.io/en/latest/_downloads/a04267077fb3fdbf2b608e014706e004/Ed-DSA.pdf
# https://asecuritysite.com/baby_jubjub/go_j_mimc7?


def mimc_permutation(r: int, k: int, rounds: int = 91) -> int:
    """
    Single-state MiMC permutation:
      for r in rounds:
        x = (x + k + c_r)^e  (mod p)
    returns final x (state)
    """
    p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    seed = b"mimc7"

    for i in range(rounds):
        c_i = int.from_bytes(sha256(seed + i.to_bytes(4, "big")).digest(), "big") % p
        # r = (r + k + c_i)^7 mod p
        r = pow((r + k + c_i) % p, 7, p)

    return (r + k) % p
