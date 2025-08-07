"""
SHA-3 海绵(Sponge)结构实现

SHA-3是基于Keccak算法的哈希函数系列，采用海绵结构。
海绵结构是一种密码学结构，能接收任意长度的输入并产生任意长度的输出。

主要组件:
- 状态: b位长的状态，分为两部分：
  - 速率部分(r): 与外部交互的部分
  - 容量部分(c): 提供安全性的部分，b = r + c
- 置换函数(f): 对整个状态进行操作的函数
- 填充规则: 确保输入能填充到r位的倍数

操作阶段:
1. 初始化：状态设置为全0
2. 吸收阶段：将输入数据分成r位的块，与状态的速率部分异或，然后应用置换函数
3. 挤出阶段：从状态的速率部分提取输出，应用置换函数，直到获得所需长度的输出

参考文献:
- FIPS 202: SHA-3 Standard
- The Keccak Reference: https://keccak.team/files/Keccak-reference-3.0.pdf
"""


# Keccak-f[1600]置换函数中使用的常量
KECCAK_ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

# Keccak轮函数中使用的旋转偏移量
KECCAK_ROTATION_OFFSETS = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]


class SHA3Sponge:
    """SHA-3海绵结构的实现，基于Keccak算法"""

    def __init__(self, rate: int, capacity: int, output_length: int):
        """
        初始化SHA-3海绵结构

        参数:
            rate: 速率(r)，与外部交互的位数，必须是8的倍数
            capacity: 容量(c)，提供安全性的位数，必须是8的倍数
            output_length: 输出长度(位)
        """
        if rate % 8 != 0:
            raise ValueError("速率(r)必须是8的倍数")
        if capacity % 8 != 0:
            raise ValueError("容量(c)必须是8的倍数")

        self.rate = rate
        self.capacity = capacity
        self.output_length = output_length

        # 状态宽度 b = r + c
        self.width = rate + capacity

        # 对于SHA-3，width通常为1600位(5x5x64)
        if self.width != 1600:
            raise ValueError("当前实现仅支持1600位宽的状态(Keccak-f[1600])")

        # 初始化状态为5x5的64位整数数组(全0)
        self.state = [[0 for _ in range(5)] for _ in range(5)]

        # 记录当前处理的字节位置
        self.position = 0

        # 是否处于挤出阶段
        self.squeezing = False

    def reset(self):
        """重置海绵状态"""
        self.state = [[0 for _ in range(5)] for _ in range(5)]
        self.position = 0
        self.squeezing = False

    def _keccak_f(self):
        """
        Keccak-f[1600]置换函数

        对当前状态执行24轮Keccak置换
        """
        lanes = self.state

        # 执行24轮
        for round_index in range(24):
            # Theta步骤
            C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
            D = [C[(x+4) % 5] ^ self._rotate_left(C[(x+1) % 5], 1) for x in range(5)]
            lanes = [[lanes[x][y] ^ D[x] for y in range(5)] for x in range(5)]

            # Rho和Pi步骤
            x, y = 1, 0
            current = lanes[x][y]
            for t in range(24):
                x, y = y, (2*x + 3*y) % 5
                current, lanes[x][y] = lanes[x][y], self._rotate_left(current, KECCAK_ROTATION_OFFSETS[x][y])

            # Chi步骤
            temp = [[0 for _ in range(5)] for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    temp[x][y] = lanes[x][y] ^ ((~lanes[(x+1) % 5][y]) & lanes[(x+2) % 5][y])
            lanes = temp

            # Iota步骤
            lanes[0][0] ^= KECCAK_ROUND_CONSTANTS[round_index]

        self.state = lanes

    def _rotate_left(self, value: int, shift: int) -> int:
        """
        64位整数的循环左移

        参数:
            value: 要旋转的64位值
            shift: 左移的位数

        返回:
            循环左移后的值
        """
        return ((value << shift) | (value >> (64 - shift))) & 0xFFFFFFFFFFFFFFFF

    def _state_to_bytes(self) -> bytes:
        """
        将状态转换为字节序列

        返回:
            表示当前状态的字节
        """
        result = bytearray()
        for y in range(5):
            for x in range(5):
                lane = self.state[x][y]
                # 将64位lane转换为8个字节(小端序)
                for i in range(8):
                    result.append((lane >> (8 * i)) & 0xFF)
        return bytes(result)

    def _absorb_block(self, block: bytes):
        """
        吸收一个块到状态中

        参数:
            block: 要吸收的字节块，长度必须等于rate/8
        """
        if len(block) * 8 != self.rate:
            raise ValueError(f"块大小必须是{self.rate//8}字节")

        # 将块与状态的速率部分异或
        rate_bytes = self.rate // 8
        for i in range(rate_bytes):
            byte_value = block[i]
            # 计算字节在状态中的位置
            x = (i % 8) % 5
            y = (i // 8) % 5
            shift = (i % 8) * 8

            # 异或到状态中
            self.state[x][y] ^= byte_value << shift

        # 应用置换函数
        self._keccak_f()

    def update(self, data: bytes):
        """
        更新海绵状态，吸收输入数据

        参数:
            data: 要处理的输入字节
        """
        if self.squeezing:
            raise ValueError("已进入挤出阶段，不能再吸收数据")

        # 处理字节
        i = 0
        rate_bytes = self.rate // 8

        # 如果有未完成的块，先完成它
        if self.position > 0:
            available = rate_bytes - self.position
            to_copy = min(available, len(data))

            # 拼接上一次剩余的字节和新数据
            buffer = bytearray(rate_bytes)
            for j in range(self.position):
                buffer[j] = 0  # 我们稍后会根据当前状态恢复这些字节

            for j in range(to_copy):
                buffer[self.position + j] = data[j]

            # 如果块已满，则处理它
            if self.position + to_copy == rate_bytes:
                self._absorb_block(buffer)
                i = to_copy
                self.position = 0
            else:
                # 否则更新位置并返回
                self.position += to_copy
                return

        # 处理完整的块
        while i + rate_bytes <= len(data):
            self._absorb_block(data[i:i+rate_bytes])
            i += rate_bytes

        # 存储剩余字节
        remaining = len(data) - i
        if remaining > 0:
            # 将剩余字节异或到状态中
            for j in range(remaining):
                byte_value = data[i + j]
                x = (j % 8) % 5
                y = (j // 8) % 5
                shift = (j % 8) * 8
                self.state[x][y] ^= byte_value << shift

            self.position = remaining

    def _pad(self):
        """
        应用填充规则并处理最后一个块

        SHA-3使用的填充规则是pad10*1
        """
        rate_bytes = self.rate // 8

        # 创建填充后的最后一个块
        padded = bytearray(rate_bytes)

        # 复制当前未处理的字节
        for i in range(self.position):
            byte_value = (self.state[i % 5][i // 5] >> ((i % 8) * 8)) & 0xFF
            padded[i] = byte_value

        # 应用pad10*1填充
        padded[self.position] = 0x06  # 对于SHA-3，使用0x06(而不是0x01)
        padded[rate_bytes - 1] |= 0x80

        # 处理填充后的块
        self._absorb_block(padded)

    def _squeeze(self, length: int) -> bytes:
        """
        从状态中挤出指定长度的字节

        参数:
            length: 要挤出的字节数

        返回:
            挤出的字节
        """
        if not self.squeezing:
            # 如果还没有进入挤出阶段，先应用填充
            self._pad()
            self.squeezing = True
            self.position = 0

        result = bytearray()
        rate_bytes = self.rate // 8

        # 如果有上次挤出的剩余字节，先收集它们
        if self.position > 0:
            available = rate_bytes - self.position
            to_take = min(available, length)

            # 从状态中提取字节
            state_bytes = self._state_to_bytes()
            for i in range(to_take):
                result.append(state_bytes[self.position + i])

            length -= to_take
            self.position += to_take

            # 如果用完了当前块，应用置换函数
            if self.position == rate_bytes:
                self._keccak_f()
                self.position = 0

        # 挤出完整的块
        while length >= rate_bytes:
            # 提取一个完整的块
            state_bytes = self._state_to_bytes()
            result.extend(state_bytes[:rate_bytes])

            # 应用置换函数
            self._keccak_f()
            length -= rate_bytes

        # 挤出剩余的字节
        if length > 0:
            state_bytes = self._state_to_bytes()
            result.extend(state_bytes[:length])
            self.position = length

        return bytes(result)

    def digest(self) -> bytes:
        """
        完成哈希计算并返回结果

        返回:
            SHA-3哈希值
        """
        # 复制当前状态，避免修改原始状态
        original_state = [row[:] for row in self.state]
        original_position = self.position
        original_squeezing = self.squeezing

        # 计算哈希值
        output_bytes = self.output_length // 8
        result = self._squeeze(output_bytes)

        # 恢复原始状态
        self.state = original_state
        self.position = original_position
        self.squeezing = original_squeezing

        return result

    def hexdigest(self) -> str:
        """
        以十六进制字符串形式返回哈希值

        返回:
            SHA-3哈希值的十六进制表示
        """
        return self.digest().hex()


def sha3_224(data: bytes = None) -> SHA3Sponge:
    """
    创建SHA3-224哈希对象

    参数:
        data: 要哈希的初始数据

    返回:
        SHA3Sponge对象
    """
    sponge = SHA3Sponge(rate=1152, capacity=448, output_length=224)
    if data:
        sponge.update(data)
    return sponge


def sha3_256(data: bytes = None) -> SHA3Sponge:
    """
    创建SHA3-256哈希对象

    参数:
        data: 要哈希的初始数据

    返回:
        SHA3Sponge对象
    """
    sponge = SHA3Sponge(rate=1088, capacity=512, output_length=256)
    if data:
        sponge.update(data)
    return sponge


def sha3_384(data: bytes = None) -> SHA3Sponge:
    """
    创建SHA3-384哈希对象

    参数:
        data: 要哈希的初始数据

    返回:
        SHA3Sponge对象
    """
    sponge = SHA3Sponge(rate=832, capacity=768, output_length=384)
    if data:
        sponge.update(data)
    return sponge


def sha3_512(data: bytes = None) -> SHA3Sponge:
    """
    创建SHA3-512哈希对象

    参数:
        data: 要哈希的初始数据

    返回:
        SHA3Sponge对象
    """
    sponge = SHA3Sponge(rate=576, capacity=1024, output_length=512)
    if data:
        sponge.update(data)
    return sponge


def shake_128(data: bytes = None) -> SHA3Sponge:
    """
    创建SHAKE128可扩展输出函数(XOF)

    参数:
        data: 要哈希的初始数据

    返回:
        SHA3Sponge对象
    """
    sponge = SHA3Sponge(rate=1344, capacity=256, output_length=0)
    if data:
        sponge.update(data)
    return sponge


def shake_256(data: bytes = None) -> SHA3Sponge:
    """
    创建SHAKE256可扩展输出函数(XOF)

    参数:
        data: 要哈希的初始数据

    返回:
        SHA3Sponge对象
    """
    sponge = SHA3Sponge(rate=1088, capacity=512, output_length=0)
    if data:
        sponge.update(data)
    return sponge


# 演示和测试
if __name__ == "__main__":
    print("=" * 50)
    print("SHA-3海绵结构演示")
    print("=" * 50)

    # 测试向量
    test_data = b"abc"

    # 测试SHA3-224
    print("\n1. SHA3-224测试")
    print("-" * 30)
    h224 = sha3_224(test_data)
    print(f"输入: {test_data}")
    print(f"SHA3-224: {h224.hexdigest()}")
    # 预期输出: e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf

    # 测试SHA3-256
    print("\n2. SHA3-256测试")
    print("-" * 30)
    h256 = sha3_256(test_data)
    print(f"输入: {test_data}")
    print(f"SHA3-256: {h256.hexdigest()}")
    # 预期输出: 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532

    # 测试SHA3-384
    print("\n3. SHA3-384测试")
    print("-" * 30)
    h384 = sha3_384(test_data)
    print(f"输入: {test_data}")
    print(f"SHA3-384: {h384.hexdigest()}")
    # 预期输出: ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25

    # 测试SHA3-512
    print("\n4. SHA3-512测试")
    print("-" * 30)
    h512 = sha3_512(test_data)
    print(f"输入: {test_data}")
    print(f"SHA3-512: {h512.hexdigest()}")
    # 预期输出: b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0

    # 测试SHAKE128
    print("\n5. SHAKE128测试")
    print("-" * 30)
    shake128 = shake_128(test_data)
    output_bytes = 32  # 输出256位
    result = shake128._squeeze(output_bytes).hex()
    print(f"输入: {test_data}")
    print(f"SHAKE128-{output_bytes*8}: {result}")

    # 测试SHAKE256
    print("\n6. SHAKE256测试")
    print("-" * 30)
    shake256 = shake_256(test_data)
    output_bytes = 64  # 输出512位
    result = shake256._squeeze(output_bytes).hex()
    print(f"输入: {test_data}")
    print(f"SHAKE256-{output_bytes*8}: {result}")

    # 测试增量更新
    print("\n7. 增量更新测试")
    print("-" * 30)
    h = sha3_256()
    h.update(b"a")
    h.update(b"b")
    h.update(b"c")
    print("增量输入: 'a' + 'b' + 'c'")
    print(f"SHA3-256: {h.hexdigest()}")
    print(f"是否与一次性输入相同: {h.hexdigest() == h256.hexdigest()}")

    print("\n" + "=" * 50)
    print("演示完成")
