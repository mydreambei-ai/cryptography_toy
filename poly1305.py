"""
Poly1305 消息认证码算法实现
基于 RFC 8439: https://datatracker.ietf.org/doc/html/rfc8439

\text{tag} = \left( \sum_{i=1}^{n} m_i \cdot r^i \mod (2^{130} - 5) \right) + s \mod 2^{128}

Poly1305 是一种消息认证码算法，用于验证消息的完整性和真实性。
它与 ChaCha20 配合使用时，可以提供认证加密功能。
"""


def clamp_r(r_bytes):
    """
    根据 RFC 8439 规范对 r 进行掩码处理

    r 的 [3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 64, 65, 66]
    位必须设置为 0，r 的第 128 位必须设置为 0
    """
    if len(r_bytes) != 16:
        raise ValueError("r_bytes must be exactly 16 bytes")

    r = int.from_bytes(r_bytes, "little")
    # 掩码处理：清除某些比特（RFC 8439 要求）
    r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    return r


def poly1305_mac(message: bytes, key: bytes) -> bytes:
    """
    计算消息的 Poly1305 认证标签

    参数:
        message: 待认证的消息
        key: 32字节密钥 (r || s)，其中 r 是前16字节，s 是后16字节

    返回:
        16字节的认证标签
    """
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("key must be 32 bytes")

    r_bytes, s_bytes = key[:16], key[16:]
    r = clamp_r(r_bytes)
    s = int.from_bytes(s_bytes, "little")

    p = (1 << 130) - 5  # Poly1305 素数: 2^130 - 5
    acc = 0

    # 将消息分成 16 字节块（Poly1305 块大小）
    for i in range(0, len(message), 16):
        block = message[i : i + 16]
        if len(block) < 16:
            # 正确处理最后一个不完整的块
            # 添加一个 0x01 字节作为分隔符，并填充0
            padded = bytearray(block)
            padded.append(0x01)
            padded.extend(b'\x00' * (16 - len(block) - 1))
            n = int.from_bytes(padded, "little")
        else:
            # 完整块加上 0x01 (2^128)
            n = int.from_bytes(block, "little") + (1 << (8 * 16))

        acc = (acc + n) * r % p

    # 添加密钥的第二部分
    acc = (acc + s) % (1 << 128)
    return acc.to_bytes(16, "little")


def verify_poly1305_tag(message: bytes, key: bytes, tag: bytes) -> bool:
    """
    验证消息的 Poly1305 认证标签

    参数:
        message: 待验证的消息
        key: 32字节密钥
        tag: 16字节认证标签

    返回:
        如果标签有效则返回 True，否则返回 False
    """
    if not isinstance(tag, bytes) or len(tag) != 16:
        raise ValueError("tag must be 16 bytes")

    # 计算预期的标签
    expected_tag = poly1305_mac(message, key)

    # 常量时间比较，防止时序攻击
    if len(expected_tag) != len(tag):
        return False

    result = 0
    for x, y in zip(expected_tag, tag):
        result |= x ^ y
    return result == 0


if __name__ == "__main__":
    # RFC 8439 测试向量
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
    )
    msg = b"Cryptographic Forum Research Group"
    expected_tag = bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9")

    tag = poly1305_mac(msg, key)
    print("Poly1305 tag:", tag.hex())
    print("Expected tag:", expected_tag.hex())
    print("Verification:", verify_poly1305_tag(msg, key, tag))

    # 测试错误的标签
    wrong_tag = bytearray(tag)
    wrong_tag[0] ^= 1  # 修改第一个字节
    print("\nWrong tag verification:", verify_poly1305_tag(msg, key, bytes(wrong_tag)))

    # 测试边界情况
    print("\n边界情况测试:")
    print("空消息:", poly1305_mac(b"", key).hex())

    # 测试块边界
    test_msg = b"x" * 15  # 15 字节 (不足一个块)
    print("15字节消息:", poly1305_mac(test_msg, key).hex())

    test_msg = b"x" * 16  # 正好一个块
    print("16字节消息:", poly1305_mac(test_msg, key).hex())

    test_msg = b"x" * 17  # 超过一个块
    print("17字节消息:", poly1305_mac(test_msg, key).hex())
