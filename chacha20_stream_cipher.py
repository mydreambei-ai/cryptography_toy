import struct
import os
from typing import Optional, Tuple

# --- ChaCha20 Stream Cipher 实现 ---
# 基于 RFC 8439: https://datatracker.ietf.org/doc/html/rfc8439
"""
ChaCha20 是由Daniel J. Bernstein设计的流密码，是Salsa20的改进版本。
它使用一个256位密钥和一个96位nonce（数字仅用一次）来加密数据。

主要特点:
1. 高速软件实现 - 比AES在软件中更快
2. 没有预计算表 - 可以防止缓存时序攻击
3. 没有分支 - 可以防止执行时序攻击
4. 每个密钥可以安全地加密巨量数据 (2^70 字节)

安全使用建议:
1. 永远不要对多个消息使用相同的(密钥,nonce)组合
2. 对于通信协议，推荐使用ChaCha20-Poly1305 AEAD构造
3. nonce可以是计数器或随机生成，但必须确保不重复
4. 在实际应用中应该使用密码学安全的随机数生成器

版本: 1.1
最后更新: 2023
"""
# --- 工具函数 ---


def rotl32(x: int, n: int) -> int:
    """
    32位整数的循环左移操作

    参数:
        x: 要旋转的32位整数
        n: 要左移的位数

    返回:
        循环左移后的结果
    """
    # 确保x在32位范围内
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))


def quarter_round(state: list, a: int, b: int, c: int, d: int) -> None:
    """
    核心 ARX (Add-Rotate-XOR) Quarter Round 操作

    这是ChaCha20算法的基本构建块，对状态矩阵的四个元素进行操作

    参数:
        state: 16个32位整数的状态数组
        a, b, c, d: 要操作的四个元素的索引
    """
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)

    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)

    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_init_state(key: bytes, counter: int, nonce: bytes) -> list:
    """
    初始化 ChaCha20 的 4x4 32位状态矩阵

    状态矩阵布局:
    cccc cccc cccc cccc  - c: 常量 "expand 32-byte k"
    kkkk kkkk kkkk kkkk  - k: 256位密钥
    kkkk kkkk kkkk kkkk
    ssss nnnn nnnn nnnn  - s: 计数器(counter), n: 96位nonce

    参数:
        key: 32字节密钥
        counter: 32位计数器，用于生成不同的keystream块
        nonce: 12字节随机数

    返回:
        包含16个32位无符号整数的状态数组

    抛出:
        ValueError: 如果密钥或nonce长度不正确
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes (96 bits)")
    if not isinstance(counter, int) or counter < 0 or counter > 0xFFFFFFFF:
        raise ValueError("Counter must be a 32-bit non-negative integer")

    constants = b"expand 32-byte k"  # ChaCha20 常量
    return (
        list(struct.unpack("<4I", constants))
        + list(struct.unpack("<8I", key))
        + [counter]
        + list(struct.unpack("<3I", nonce))
    )


def chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """
    生成一个 64 字节 ChaCha20 keystream block

    参数:
        key: 32字节密钥
        counter: 32位计数器，用于生成不同的keystream块
        nonce: 12字节随机数

    返回:
        64字节的keystream block

    抛出:
        ValueError: 如果密钥或nonce长度不正确，或计数器无效
    """
    # 初始化状态矩阵
    state = chacha20_init_state(key, counter, nonce)
    working = state.copy()  # 创建工作状态的副本

    # ChaCha20 使用20轮变换（10次迭代，每次包括列轮和对角线轮）
    for _ in range(10):  # 10次迭代，每次迭代包含column和diagonal两轮
        # Column round - 对每列进行quarter_round操作
        quarter_round(working, 0, 4, 8, 12)
        quarter_round(working, 1, 5, 9, 13)
        quarter_round(working, 2, 6, 10, 14)
        quarter_round(working, 3, 7, 11, 15)

        # Diagonal round - 对每个对角线进行quarter_round操作
        quarter_round(working, 0, 5, 10, 15)
        quarter_round(working, 1, 6, 11, 12)
        quarter_round(working, 2, 7, 8, 13)
        quarter_round(working, 3, 4, 9, 14)

    # 将原始状态与变换后的状态相加
    output = [(x + y) & 0xFFFFFFFF for x, y in zip(state, working)]
    # 将32位整数数组打包为字节序列
    return struct.pack("<16I", *output)  # 64 字节 keystream block


def chacha20_encrypt(key: bytes, nonce: bytes, data: bytes, counter: int = 1) -> bytes:
    """
    ChaCha20流加密/解密：数据 ⊕ keystream

    由于XOR操作的特性，加密和解密使用相同的函数

    参数:
        key: 32字节密钥
        nonce: 12字节随机数
        data: 待加密/解密数据
        counter: 初始计数器值(默认为1)

    返回:
        加密/解密后的数据

    抛出:
        ValueError: 如果密钥或nonce长度不正确
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes (96 bits)")
    if not isinstance(counter, int) or counter < 0 or counter > 0xFFFFFFFF:
        raise ValueError("Counter must be a 32-bit non-negative integer")

    # 高效地预分配输出缓冲区
    result = bytearray(len(data))

    # 逐块处理数据
    for block_index in range((len(data) + 63) // 64):
        # 生成keystream块
        keystream = chacha20_block(key, counter + block_index, nonce)

        # 确定当前块的范围
        start_idx = block_index * 64
        end_idx = min(start_idx + 64, len(data))
        block_size = end_idx - start_idx

        # 将数据与keystream进行XOR操作
        for i in range(block_size):
            result[start_idx + i] = data[start_idx + i] ^ keystream[i]

    return bytes(result)


def poly1305_key_gen(key: bytes, nonce: bytes) -> bytes:
    """
    生成Poly1305认证密钥

    根据RFC 8439, ChaCha20-Poly1305 AEAD使用ChaCha20的第0个block(counter=0)
    作为Poly1305的一次性认证密钥

    参数:
        key: 32字节ChaCha20密钥
        nonce: 12字节随机数

    返回:
        32字节Poly1305密钥

    抛出:
        ValueError: 如果密钥或nonce长度不正确
    """
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes (96 bits)")

    return chacha20_block(key, 0, nonce)[:32]


def pad16(data: bytes) -> bytes:
    """
    将数据填充到16字节的倍数

    参数:
        data: 要填充的数据

    返回:
        填充字节，使data长度达到16的倍数
    """
    if len(data) % 16 == 0:
        return b""
    return b"\x00" * (16 - (len(data) % 16))


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    """
    ChaCha20-Poly1305 AEAD加密

    按照RFC 8439规范实现的认证加密算法

    参数:
        key: 32字节密钥
        nonce: 12字节随机数
        plaintext: 明文数据
        aad: 附加认证数据(可选)

    返回:
        (ciphertext, tag): 密文和16字节认证标签的元组

    抛出:
        ValueError: 如果密钥或nonce长度不正确
        ImportError: 如果找不到poly1305模块
    """
    # 参数验证
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes (96 bits)")
    if not isinstance(plaintext, bytes):
        raise TypeError("Plaintext must be bytes")
    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes")

    # 导入poly1305模块实现
    try:
        from poly1305 import poly1305_mac
    except ImportError:
        raise ImportError("poly1305 module is required for AEAD operation")

    # 1. 生成Poly1305一次性密钥
    poly_key = poly1305_key_gen(key, nonce)

    # 2. 使用ChaCha20加密明文(counter从1开始)
    ciphertext = chacha20_encrypt(key, nonce, plaintext, counter=1)

    # 3. 计算认证标签
    # 构建认证数据
    mac_data = (
        aad + pad16(aad) +
        ciphertext + pad16(ciphertext) +
        struct.pack("<Q", len(aad)) +
        struct.pack("<Q", len(ciphertext))
    )

    # 计算认证标签
    tag = poly1305_mac(mac_data, poly_key)

    return ciphertext, tag


def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes,
                             tag: bytes, aad: bytes = b"") -> Optional[bytes]:
    """
    ChaCha20-Poly1305 AEAD解密

    按照RFC 8439规范实现的认证解密算法

    参数:
        key: 32字节密钥
        nonce: 12字节随机数
        ciphertext: 密文数据
        tag: 16字节认证标签
        aad: 附加认证数据(可选)

    返回:
        解密后的明文，如果认证失败则返回None

    抛出:
        ValueError: 如果密钥、nonce或tag长度不正确
        ImportError: 如果找不到poly1305模块
    """
    # 参数验证
    if not isinstance(key, bytes) or len(key) != 32:
        raise ValueError("Key must be 32 bytes (256 bits)")
    if not isinstance(nonce, bytes) or len(nonce) != 12:
        raise ValueError("Nonce must be 12 bytes (96 bits)")
    if not isinstance(ciphertext, bytes):
        raise TypeError("Ciphertext must be bytes")
    if not isinstance(tag, bytes) or len(tag) != 16:
        raise ValueError("Tag must be 16 bytes")
    if not isinstance(aad, bytes):
        raise TypeError("AAD must be bytes")

    # 导入poly1305模块
    try:
        from poly1305 import poly1305_mac, verify_poly1305_tag
    except ImportError:
        from poly1305 import poly1305_mac
        # 如果verify_poly1305_tag不可用，将使用bytes_constant_time_compare

    # 1. 生成Poly1305一次性密钥
    poly_key = poly1305_key_gen(key, nonce)

    # 2. 验证认证标签
    # 构建认证数据
    mac_data = (
        aad + pad16(aad) +
        ciphertext + pad16(ciphertext) +
        struct.pack("<Q", len(aad)) +
        struct.pack("<Q", len(ciphertext))
    )

    # 计算并验证认证标签
    try:
        # 如果verify_poly1305_tag可用，使用它
        if not verify_poly1305_tag(mac_data, poly_key, tag):
            return None  # 认证失败
    except NameError:
        # 否则使用我们自己的常量时间比较
        expected_tag = poly1305_mac(mac_data, poly_key)
        if not bytes_constant_time_compare(expected_tag, tag):
            return None  # 认证失败

    # 3. 解密
    return chacha20_encrypt(key, nonce, ciphertext, counter=1)


def bytes_constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    常量时间比较两个字节串，防止时序攻击

    无论输入如何，此函数总是花费相同的时间执行，
    这样可以防止基于时间的侧信道攻击。

    参数:
        a, b: 要比较的两个字节串

    返回:
        如果两个字节串相等则返回True，否则返回False
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False

    if len(a) != len(b):
        return False

    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# 生成随机密钥和nonce的辅助函数
def generate_key() -> bytes:
    """
    生成256位随机密钥

    使用操作系统的密码学安全随机数生成器

    返回:
        32字节随机密钥
    """
    try:
        return os.urandom(32)
    except (AttributeError, NotImplementedError):
        raise RuntimeError("无法生成安全的随机密钥 - 系统不支持os.urandom")


def generate_nonce() -> bytes:
    """
    生成96位随机nonce

    使用操作系统的密码学安全随机数生成器

    返回:
        12字节随机nonce
    """
    try:
        return os.urandom(12)
    except (AttributeError, NotImplementedError):
        raise RuntimeError("无法生成安全的随机nonce - 系统不支持os.urandom")


def encrypt_file(input_file: str, output_file: str, key: bytes, nonce: bytes,
                use_aead: bool = True) -> None:
    """
    加密文件

    参数:
        input_file: 输入文件路径
        output_file: 输出文件路径
        key: 32字节密钥
        nonce: 12字节nonce
        use_aead: 是否使用AEAD模式(默认为True)
    """
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    if use_aead:
        ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, plaintext)
        with open(output_file, 'wb') as f:
            f.write(nonce)  # 存储nonce
            f.write(tag)    # 存储认证标签
            f.write(ciphertext)
    else:
        ciphertext = chacha20_encrypt(key, nonce, plaintext)
        with open(output_file, 'wb') as f:
            f.write(nonce)  # 存储nonce
            f.write(ciphertext)


def decrypt_file(input_file: str, output_file: str, key: bytes,
                use_aead: bool = True) -> bool:
    """
    解密文件

    参数:
        input_file: 加密文件路径
        output_file: 输出文件路径
        key: 32字节密钥
        use_aead: 是否使用AEAD模式(默认为True)

    返回:
        解密成功返回True，否则返回False
    """
    with open(input_file, 'rb') as f:
        if use_aead:
            nonce = f.read(12)  # 读取nonce
            tag = f.read(16)    # 读取认证标签
            ciphertext = f.read()  # 读取剩余的密文

            plaintext = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag)
            if plaintext is None:
                return False  # 认证失败
        else:
            nonce = f.read(12)  # 读取nonce
            ciphertext = f.read()  # 读取剩余的密文
            plaintext = chacha20_encrypt(key, nonce, ciphertext)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

    return True


class ChaCha20Cipher:
    """ChaCha20加密类，提供面向对象的接口"""

    def __init__(self, key: bytes = None, nonce: bytes = None):
        """
        初始化ChaCha20加密器

        参数:
            key: 可选的32字节密钥，如不提供则自动生成
            nonce: 可选的12字节nonce，如不提供则自动生成
        """
        self.key = key if key is not None else generate_key()
        self.nonce = nonce if nonce is not None else generate_nonce()

    def encrypt(self, data: bytes, counter: int = 1) -> bytes:
        """
        加密数据

        参数:
            data: 待加密数据
            counter: 初始计数器值

        返回:
            加密后的数据
        """
        return chacha20_encrypt(self.key, self.nonce, data, counter)

    def decrypt(self, data: bytes, counter: int = 1) -> bytes:
        """
        解密数据

        参数:
            data: 待解密数据
            counter: 初始计数器值

        返回:
            解密后的数据
        """
        return chacha20_encrypt(self.key, self.nonce, data, counter)

    def encrypt_aead(self, data: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """
        AEAD模式加密

        参数:
            data: 待加密数据
            aad: 附加认证数据

        返回:
            (密文, 认证标签)元组
        """
        return chacha20_poly1305_encrypt(self.key, self.nonce, data, aad)

    def decrypt_aead(self, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> Optional[bytes]:
        """
        AEAD模式解密

        参数:
            ciphertext: 密文
            tag: 认证标签
            aad: 附加认证数据

        返回:
            解密后的明文，认证失败时返回None
        """
        return chacha20_poly1305_decrypt(self.key, self.nonce, ciphertext, tag, aad)


if __name__ == "__main__":
    print("=" * 50)
    print("ChaCha20 测试和演示")
    print("=" * 50)

    # === 1. RFC 8439 测试向量验证 ===
    print("\n1. RFC 8439 测试向量验证")
    print("-" * 30)
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ])
    nonce = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00])
    counter = 1

    # 生成一个keystream block进行验证
    keystream = chacha20_block(key, counter, nonce)
    print("Keystream block (前16字节):", keystream[:16].hex())
    # 期望结果: 224f51f3401bd9e12fde276fb8631ded

    # === 2. 基本加密和解密演示 ===
    print("\n2. 基本加密和解密演示")
    print("-" * 30)
    message = b"ChaCha20 stream cipher demo, secure and fast!"  # 明文
    print("原文:", message.decode())

    ciphertext = chacha20_encrypt(key, nonce, message)
    print("密文 (hex):", ciphertext.hex())

    decrypted = chacha20_encrypt(key, nonce, ciphertext)  # 再加密一次即解密
    print("解密后:", decrypted.decode())

    # 验证解密结果正确性
    assert decrypted == message, "解密结果与原文不匹配!"

    # === 3. Nonce重要性演示 ===
    print("\n3. Nonce重要性演示")
    print("-" * 30)
    print("使用相同密钥但不同nonce:")
    nonce2 = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00])
    ciphertext2 = chacha20_encrypt(key, nonce2, message)
    print("不同nonce的密文 (hex):", ciphertext2.hex())

    # 验证不同nonce产生不同密文
    assert ciphertext != ciphertext2, "不同nonce应产生不同密文!"

    # === 4. ChaCha20-Poly1305 AEAD 演示 ===
    print("\n4. ChaCha20-Poly1305 AEAD 演示")
    print("-" * 30)
    # 生成随机密钥和nonce
    key = generate_key()
    nonce = generate_nonce()
    message = b"ChaCha20-Poly1305 AEAD provides both confidentiality and authenticity!"
    aad = b"Additional authenticated data"

    # 加密和认证
    ciphertext, tag = chacha20_poly1305_encrypt(key, nonce, message, aad)

    print("密文 (hex):", ciphertext.hex())
    print("认证标签 (hex):", tag.hex())

    # 解密和验证
    decrypted = chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad)
    print("解密后:", decrypted.decode())

    # 验证解密结果正确性
    assert decrypted == message, "AEAD解密结果与原文不匹配!"

    # === 5. 篡改检测演示 ===
    print("\n5. 篡改检测演示")
    print("-" * 30)
    # 篡改密文
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1  # 修改第一个字节

    # 尝试解密篡改的密文
    decrypted_tampered = chacha20_poly1305_decrypt(key, nonce, bytes(tampered), tag, aad)
    if decrypted_tampered is None:
        print("篡改检测成功: 认证失败")
    else:
        print("篡改检测失败!")

    # === 6. 面向对象接口演示 ===
    print("\n6. 面向对象接口演示")
    print("-" * 30)
    cipher = ChaCha20Cipher()

    test_data = b"Testing object-oriented interface for ChaCha20"
    print("原文:", test_data.decode())

    # 普通加密模式
    encrypted = cipher.encrypt(test_data)
    decrypted = cipher.decrypt(encrypted)
    print("普通模式解密结果:", decrypted.decode())

    # AEAD模式
    aead_encrypted, tag = cipher.encrypt_aead(test_data, b"OO Interface AAD")
    aead_decrypted = cipher.decrypt_aead(aead_encrypted, tag, b"OO Interface AAD")
    print("AEAD模式解密结果:", aead_decrypted.decode())

    # 验证两种模式解密结果正确性
    assert decrypted == test_data
    assert aead_decrypted == test_data

    print("\n所有测试通过!")
