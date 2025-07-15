"""
\text{tag} = \left( \sum_{i=1}^{n} m_i \cdot r^i \mod (2^{130} - 5) \right) + s \mod 2^{128}

"""


def clamp_r(r_bytes):
    r = int.from_bytes(r_bytes, "little")
    # 掩码处理：清除某些比特（RFC 8439 要求）
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    return r


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    assert len(key) == 32
    r_bytes, s_bytes = key[:16], key[16:]
    r = clamp_r(r_bytes)
    s = int.from_bytes(s_bytes, "little")

    p = (1 << 130) - 5
    acc = 0

    # 将消息分成 16 字节块（Poly1305 块大小）
    for i in range(0, len(message), 16):
        block = message[i : i + 16]
        n = int.from_bytes(block + b"\x01", "little")  # 填充一个 0x01
        acc = (acc + n) * r % p

    acc = (acc + s) % (1 << 128)
    return acc.to_bytes(16, "little")


if __name__ == "__main__":
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    msg = b"Cryptographic Forum Research Group"

    tag = poly1305_mac(msg, key)
    print("Poly1305 tag:", tag.hex())
