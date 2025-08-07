"""
Feistel 结构实现

Feistel 结构是许多对称密码算法的基础，如 DES、Blowfish 等。
它的主要特点是加密和解密操作几乎相同，只是轮密钥的使用顺序相反。

特性:
- 无需F函数可逆
- 加密和解密过程高度相似
- 可构建平衡或非平衡的Feistel网络
- 适用于硬件实现

设计模式:
- 可定制F函数
- 灵活的轮数
- 支持不同位长数据块
"""

import hashlib
import secrets
from typing import Callable, List, Optional, Tuple, Union


class FeistelNetwork:
    """Feistel 网络的通用实现，支持自定义参数和配置"""

    def __init__(
        self,
        block_size: int = 64,
        rounds: int = 16,
        f_function: Optional[Callable] = None,
        key_schedule: Optional[Callable] = None,
    ):
        """
        初始化 Feistel 网络

        参数:
            block_size: 块大小(位)，必须是偶数且至少为16位
            rounds: 轮数，建议至少为8轮
            f_function: 自定义的F函数，接收(数据块, 轮密钥)作为参数
            key_schedule: 自定义的密钥调度算法，从主密钥生成轮密钥
        """
        if block_size % 2 != 0 or block_size < 16:
            raise ValueError("块大小必须是偶数且至少为16位")
        if rounds < 1:
            raise ValueError("轮数必须为正数")

        self.block_size = block_size
        self.half_size = block_size // 2
        self.half_bytes = self.half_size // 8
        self.max_value = (1 << self.half_size) - 1
        self.rounds = rounds

        # 设置默认或自定义的F函数
        self.f_function = f_function if f_function else self._default_f_function

        # 设置默认或自定义的密钥调度算法
        self.key_schedule = key_schedule if key_schedule else self._default_key_schedule

        # 内部状态
        self.round_keys = []

    def _default_f_function(self, data: int, key: int) -> int:
        """
        默认的F函数实现，使用异或和循环移位操作

        注意：F函数必须产生可预测且一致的输出，不应依赖于加密/解密方向

        参数:
            data: 半块数据
            key: 轮密钥

        返回:
            F函数输出
        """
        # 异或操作
        result = data ^ key

        # 循环左移5位
        rotated = ((result << 5) | (result >> (self.half_size - 5))) & self.max_value

        # 与原始值异或
        return (rotated ^ data) & self.max_value

    def _default_key_schedule(self, master_key: bytes, rounds: int) -> List[int]:
        """
        默认的密钥调度算法，使用哈希函数生成轮密钥

        参数:
            master_key: 主密钥
            rounds: 轮数

        返回:
            轮密钥列表
        """
        round_keys = []
        current = master_key

        for i in range(rounds):
            # 使用哈希函数生成不同的轮密钥
            h = hashlib.sha256(current + bytes([i])).digest()

            # 从哈希值中提取适当大小的轮密钥
            if self.half_size <= 32:
                # 对于小于等于32位的半块，取哈希前几个字节
                bytes_needed = self.half_bytes
                key_int = int.from_bytes(h[:bytes_needed], byteorder='big') & self.max_value
            else:
                # 对于大于32位的半块，需要使用多个哈希值
                key_int = 0
                bytes_needed = self.half_bytes
                for j in range(0, bytes_needed, 4):
                    chunk = min(4, bytes_needed - j)
                    key_chunk = int.from_bytes(h[j:j+chunk], byteorder='big')
                    key_int = (key_int << (chunk * 8)) | key_chunk

                key_int &= self.max_value

            round_keys.append(key_int)
            current = h  # 用当前哈希作为下一轮的输入

        return round_keys

    def set_key(self, key: Union[bytes, str]) -> None:
        """
        设置密钥并生成轮密钥

        参数:
            key: 密钥，可以是字节或字符串
        """
        if isinstance(key, str):
            key = key.encode('utf-8')

        # 使用密钥调度算法生成轮密钥
        self.round_keys = self.key_schedule(key, self.rounds)

    def generate_key(self) -> bytes:
        """
        生成一个随机密钥并设置它

        返回:
            生成的密钥
        """
        # 生成足够长的随机密钥
        key_bytes = secrets.token_bytes(32)  # 256位密钥
        self.set_key(key_bytes)
        return key_bytes

    def _split_block(self, block: int) -> Tuple[int, int]:
        """
        将块分割为左右两半

        参数:
            block: 完整的数据块

        返回:
            (左半块, 右半块)
        """
        right = block & self.max_value
        left = (block >> self.half_size) & self.max_value
        return left, right

    def _combine_block(self, left: int, right: int) -> int:
        """
        将左右两半合并为完整块

        参数:
            left: 左半块
            right: 右半块

        返回:
            合并后的完整块
        """
        return ((left & self.max_value) << self.half_size) | (right & self.max_value)

    def encrypt_block(self, block: int) -> int:
        """
        加密单个数据块

        参数:
            block: 明文块

        返回:
            密文块
        """
        if not self.round_keys:
            raise ValueError("必须先设置密钥")

        left, right = self._split_block(block)

        # Feistel轮函数
        for i in range(self.rounds):
            f_out = self.f_function(right, self.round_keys[i])
            # 确保f_out不超出半块大小
            f_out &= self.max_value
            left, right = right, left ^ f_out

        # Feistel网络的最后一轮后需要交换左右两半
        return self._combine_block(right, left)

    def decrypt_block(self, block: int) -> int:
        """
        解密单个数据块

        参数:
            block: 密文块

        返回:
            明文块
        """
        if not self.round_keys:
            raise ValueError("必须先设置密钥")

        left, right = self._split_block(block)

        # Feistel轮函数，使用相反顺序的轮密钥
        for i in range(self.rounds - 1, -1, -1):
            f_out = self.f_function(left, self.round_keys[i])
            # 确保f_out不超出半块大小
            f_out &= self.max_value
            right, left = left, right ^ f_out

        return self._combine_block(left, right)

    def encrypt(self, data: bytes) -> bytes:
        """
        加密任意长度的数据

        参数:
            data: 明文数据

        返回:
            密文数据
        """
        if not data:
            return b''

        # 确定块大小（字节）
        block_bytes = self.block_size // 8

        # PKCS#7填充
        # 始终添加填充，即使数据长度是块大小的倍数
        # 这样保证解密时始终可以去除填充
        padding_length = block_bytes - (len(data) % block_bytes)
        if padding_length == 0:
            padding_length = block_bytes

        padded_data = data + bytes([padding_length]) * padding_length

        # 逐块加密
        result = bytearray()
        for i in range(0, len(padded_data), block_bytes):
            block = int.from_bytes(padded_data[i:i+block_bytes], byteorder='big')
            encrypted_block = self.encrypt_block(block)
            result.extend(encrypted_block.to_bytes(block_bytes, byteorder='big'))

        return bytes(result)

    def decrypt(self, data: bytes) -> bytes:
        """
        解密数据

        参数:
            data: 密文数据

        返回:
            明文数据
        """
        if not data:
            return b''

        # 确定块大小（字节）
        block_bytes = self.block_size // 8

        if len(data) % block_bytes != 0:
            raise ValueError("数据长度必须是块大小的倍数")

        # 逐块解密
        result = bytearray()
        for i in range(0, len(data), block_bytes):
            block = int.from_bytes(data[i:i+block_bytes], byteorder='big')
            decrypted_block = self.decrypt_block(block)
            result.extend(decrypted_block.to_bytes(block_bytes, byteorder='big'))

        # 安全地移除PKCS#7填充
        if not result:
            raise ValueError("解密后数据为空，无法验证填充")

        # 获取填充长度
        padding_length = result[-1]

        # 验证填充长度是否合理
        if padding_length == 0 or padding_length > block_bytes:
            raise ValueError(f"无效的填充长度: {padding_length}")

        # 确保数据长度至少等于填充长度
        if len(result) < padding_length:
            raise ValueError("数据长度小于填充长度，无效的填充")

        # 验证所有填充字节是否一致
        padding = result[-padding_length:]
        expected_padding = bytes([padding_length]) * padding_length

        if padding != expected_padding:
            raise ValueError("填充字节不一致，可能是无效的填充或密钥错误")

        # 移除填充
        return bytes(result[:-padding_length])


# 兼容旧版本的函数接口
def F(right: int, key: int) -> int:
    """
    兼容旧版本的F函数

    参数:
        right: 右半块
        key: 轮密钥

    返回:
        F函数输出
    """
    return (right ^ key) & 0xFFFFFFFF


def feistel_encrypt_block(block: int, round_keys: List[int]) -> int:
    """
    兼容旧版本的单块加密函数

    参数:
        block: 明文块
        round_keys: 轮密钥列表

    返回:
        密文块
    """
    left = (block >> 32) & 0xFFFFFFFF
    right = block & 0xFFFFFFFF

    for key in round_keys:
        f_out = F(right, key)
        left, right = right, left ^ f_out

    # 注意：Feistel 网络中，加密结束后是 (R, L)
    return (right << 32) | left


def feistel_decrypt_block(block: int, round_keys: List[int]) -> int:
    """
    兼容旧版本的单块解密函数

    参数:
        block: 密文块
        round_keys: 轮密钥列表

    返回:
        明文块
    """
    right = (block >> 32) & 0xFFFFFFFF
    left = block & 0xFFFFFFFF

    for key in reversed(round_keys):
        f_out = F(left, key)
        right, left = left, right ^ f_out

    return (left << 32) | right


def create_blowfish_like() -> FeistelNetwork:
    """
    创建一个类似Blowfish的Feistel网络配置

    返回:
        配置好的FeistelNetwork实例
    """
    def blowfish_f(data: int, key: int) -> int:
        """简化的Blowfish F函数"""
        # 分割数据为4个字节
        a = (data >> 24) & 0xFF
        b = (data >> 16) & 0xFF
        c = (data >> 8) & 0xFF
        d = data & 0xFF

        # 模拟S盒查找和混合操作
        # 使用加法和异或代替乘法，确保操作的一致性
        result = ((a + b) % 256) ^ ((c + d) % 256)
        result = ((result << 8) | result) & 0xFFFF
        result = ((result << 16) | result) & 0xFFFFFFFF

        return (result ^ key) & 0xFFFFFFFF

    network = FeistelNetwork(block_size=64, rounds=16, f_function=blowfish_f)
    return network


def create_des_like() -> FeistelNetwork:
    """
    创建一个类似DES的Feistel网络配置

    返回:
        配置好的FeistelNetwork实例
    """
    # DES使用32位的半块和48位的轮密钥
    # 这里我们简化实现
    def des_f(data: int, key: int) -> int:
        """简化的DES F函数"""
        # 扩展置换（简化）
        expanded = ((data << 1) | (data >> 31)) & 0xFFFFFFFF

        # 与轮密钥异或
        mixed = expanded ^ key

        # 模拟S盒替换（简化）
        s_box_output = 0
        for i in range(8):
            chunk = (mixed >> (28 - i*4)) & 0xF
            # 简单的S盒操作：使用异或和加法代替乘法，确保一致性
            s_box_result = ((chunk ^ 0x5) + 3) % 16
            s_box_output |= s_box_result << (28 - i*4)

        # 模拟P置换（简化）
        p_output = ((s_box_output << 11) | (s_box_output >> 21)) & 0xFFFFFFFF

        return p_output

    network = FeistelNetwork(block_size=64, rounds=16, f_function=des_f)
    return network


if __name__ == "__main__":
    print("=" * 50)
    print("Feistel网络演示")
    print("=" * 50)

    # 演示原始函数接口
    print("\n1. 原始函数接口演示")
    print("-" * 30)
    plaintext = 0x0123456789ABCDEF
    round_keys = [0x0F1571C9, 0x47D9E859, 0x0CB7ADD6, 0xAF7F6798]

    ciphertext = feistel_encrypt_block(plaintext, round_keys)
    decrypted = feistel_decrypt_block(ciphertext, round_keys)

    print(f"明文:  {hex(plaintext)}")
    print(f"密文:  {hex(ciphertext)}")
    print(f"解密:  {hex(decrypted)}")
    print(f"验证:  {plaintext == decrypted}")

    # 验证结果的正确性
    if plaintext != decrypted:
        print("警告: 解密结果与原始明文不匹配!")

    # 演示面向对象接口
    print("\n2. 面向对象接口演示")
    print("-" * 30)
    # 创建默认配置的Feistel网络
    feistel = FeistelNetwork(block_size=64, rounds=8)
    key = feistel.generate_key()
    print(f"随机密钥: {key.hex()[:16]}...")

    test_data = b"Hello, Feistel Network!"
    print(f"原始数据: {test_data}")

    try:
        encrypted = feistel.encrypt(test_data)
        print(f"加密数据: {encrypted.hex()[:32]}...")

        decrypted = feistel.decrypt(encrypted)
        print(f"解密数据: {decrypted}")
        print(f"验证:     {test_data == decrypted}")

    except Exception as e:
        print(f"错误: {e}")

    # 演示自定义F函数
    print("\n3. 自定义F函数演示")
    print("-" * 30)

    def custom_f(data, key):
        # 自定义的复杂F函数
        # 注意：确保操作是可逆的或不依赖于方向
        # 异或操作是可逆的，循环移位是可逆的
        # 乘法操作可能导致信息丢失，应避免在Feistel结构的F函数中使用
        result = data ^ key
        result = ((result << 7) | (result >> 25)) & 0xFFFFFFFF
        # 避免使用乘法，改为另一个异或操作
        result = result ^ ((result << 13) | (result >> 19)) & 0xFFFFFFFF
        return result

    custom_feistel = FeistelNetwork(block_size=64, rounds=12, f_function=custom_f)
    custom_feistel.set_key(b"my-secure-key-123")

    test_block = 0x0123456789ABCDEF
    print(f"测试块:   {hex(test_block)}")

    try:
        enc_block = custom_feistel.encrypt_block(test_block)
        print(f"加密块:   {hex(enc_block)}")

        dec_block = custom_feistel.decrypt_block(enc_block)
        print(f"解密块:   {hex(dec_block)}")
        print(f"验证:     {test_block == dec_block}")

        if test_block != dec_block:
            print(f"警告: 解密结果不匹配。原始值: {hex(test_block)}, 解密值: {hex(dec_block)}")
            print(f"差异位: {bin(test_block ^ dec_block)}")
    except Exception as e:
        print(f"自定义F函数测试错误: {e}")

    # 演示预配置的密码
    print("\n4. 预配置密码演示")
    print("-" * 30)

    print("A. 类Blowfish配置")
    blowfish = create_blowfish_like()
    blowfish.set_key(b"blowfish-key")

    test_data = b"Blowfish test data with padding to make it longer"
    try:
        enc_data = blowfish.encrypt(test_data)
        dec_data = blowfish.decrypt(enc_data)

        print(f"加密长度: {len(enc_data)} 字节")
        print(f"验证:     {test_data == dec_data}")
    except Exception as e:
        print(f"Blowfish测试错误: {e}")

    print("\nB. 类DES配置")
    des = create_des_like()
    des.set_key(b"des-key!!!")

    test_data = b"DES test with different data"
    try:
        enc_data = des.encrypt(test_data)
        dec_data = des.decrypt(enc_data)

        print(f"加密长度: {len(enc_data)} 字节")
        print(f"验证:     {test_data == dec_data}")
    except Exception as e:
        print(f"DES测试错误: {e}")

    print("\n" + "=" * 50)
    print("演示完成")
