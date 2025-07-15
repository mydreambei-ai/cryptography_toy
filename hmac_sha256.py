import hashlib


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """
    HMACkey(message)=H((key⊕opad)∣∣H((key⊕ipad)∣∣message))
    """

    block_size = 64  # SHA-256 block size = 512 bits = 64 bytes

    # 1. 如果 key 太长，就先 hash 它
    if len(key) > block_size:
        key = hashlib.sha256(key).digest()

    # 2. 如果 key 太短，就用 0x00 补齐
    if len(key) < block_size:
        key = key + b"\x00" * (block_size - len(key))

    # 3. 定义 ipad 和 opad
    ipad = bytes((x ^ 0x36) for x in key)
    opad = bytes((x ^ 0x5C) for x in key)

    # 4. 执行 HMAC 结构： H(opad || H(ipad || message))
    inner_hash = hashlib.sha256(ipad + message).digest()
    outer_hash = hashlib.sha256(opad + inner_hash).digest()

    return outer_hash


if __name__ == "__main__":
    key = b"secret-key-123"
    message = b"This is the message to authenticate."

    mac = hmac_sha256(key, message)
    print("HMAC-SHA256:", mac.hex())
