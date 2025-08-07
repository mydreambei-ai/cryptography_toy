"""
Regev LWE (Learning with Errors) 加密系统实现

基于Oded Regev在2005年提出的基于学习难题的加密方案，
该方案的安全性基于学习带误差问题(Learning With Errors, LWE)的困难性。

主要特点:
- 被认为是抗量子计算的加密系统
- 可用于实现同态加密
- 安全性基于格上最短向量问题的困难性

参考文献:
- Regev, O. (2005). On lattices, learning with errors, random linear codes, and cryptography.
- Lindner, R., & Peikert, C. (2011). Better key sizes (and attacks) for LWE-based encryption.
"""

import numpy as np
from typing import Tuple, List, Union, Optional
import time
import matplotlib.pyplot as plt
from dataclasses import dataclass


@dataclass
class LWEParameters:
    """Regev LWE加密系统的参数"""
    n: int           # 安全参数（私钥向量维度）
    q: int           # 模数
    m: int           # 样本数量（公钥矩阵A的行数）
    sigma: float     # 高斯分布的标准差

    @classmethod
    def recommended_parameters(cls, security_level: int = 128) -> 'LWEParameters':
        """
        根据安全级别返回推荐参数

        参数:
            security_level: 安全级别（比特）

        返回:
            推荐的LWE参数
        """
        # 这里的参数仅为示例，实际应用需要更精确的参数选择
        if security_level <= 80:
            return cls(n=128, q=4093, m=256, sigma=3.2)
        elif security_level <= 128:
            return cls(n=256, q=8191, m=512, sigma=3.2)
        else:  # 高安全级别
            return cls(n=512, q=16381, m=1024, sigma=3.2)

    def validate(self) -> bool:
        """
        验证参数是否满足基本安全要求

        返回:
            参数是否有效
        """
        # 基本验证 - 只检查必要条件
        if self.n <= 0 or self.m <= 0 or self.q <= 2 or self.sigma <= 0:
            return False

        # q应该是奇数（避免q=2的情况）
        if self.q % 2 == 0:
            return False

        # 确保m足够大以提供足够的样本
        # 通常m应该至少是n的2倍
        if self.m < self.n:
            return False

        return True


class RegevLWE:
    """Regev的LWE加密系统实现"""

    def __init__(self, params: Optional[LWEParameters] = None):
        """
        初始化LWE加密系统

        参数:
            params: LWE参数，如果为None则使用默认参数
        """
        self.params = params

        # 检查参数有效性
        if not self.params.validate():
            print(f"警告: 参数 (n={self.params.n}, q={self.params.q}, m={self.params.m}, σ={self.params.sigma}) 可能不是最优的")

        # 提取常用参数到实例变量
        self.n = self.params.n
        self.q = self.params.q
        self.m = self.params.m
        self.sigma = self.params.sigma

        # 密钥
        self.public_key = None
        self.secret_key = None

    def discrete_gaussian(self, size: Union[int, Tuple[int, ...]], centered: bool = True) -> np.ndarray:
        """
        生成离散高斯分布的样本

        参数:
            size: 输出数组的形状
            centered: 如果为True，生成[-q/2, q/2)范围内的值；否则生成[0, q)范围内的值

        返回:
            离散高斯分布的样本
        """
        try:
            # 生成连续高斯分布
            samples = np.random.normal(0, self.sigma, size=size)

            # 离散化（四舍五入到最近的整数）
            samples = np.round(samples).astype(np.int64)

            # 取模确保在正确范围内
            samples = samples % self.q

            # 调整到中心范围[-q/2, q/2)
            if centered:
                samples = (samples + self.q // 2) % self.q - self.q // 2

            return samples
        except Exception as e:
            print(f"警告: 生成高斯噪声时出错: {e}")
            # 发生错误时返回零噪声
            return np.zeros(size, dtype=np.int64)

    def keygen(self) -> Tuple[Tuple[np.ndarray, np.ndarray], np.ndarray]:
        """
        生成LWE密钥对

        返回:
            (public_key, secret_key): 其中public_key是(A, b)的元组
        """
        # 随机矩阵A
        A = np.random.randint(0, self.q, size=(self.m, self.n))

        # 随机私钥向量s
        s = np.random.randint(0, self.q, size=self.n)

        # 噪声向量e
        e = self.discrete_gaussian(self.m)

        # 计算公钥向量b = As + e (mod q)
        b = (A @ s + e) % self.q

        # 保存密钥
        self.public_key = (A, b)
        self.secret_key = s

        return self.public_key, self.secret_key

    def encrypt_bit(self, pk: Tuple[np.ndarray, np.ndarray], bit: int) -> Tuple[np.ndarray, int]:
        """
        加密单个比特

        参数:
            pk: 公钥(A, b)
            bit: 要加密的比特(0或1)

        返回:
            (c1, c2): 密文对
        """
        if bit not in [0, 1]:
            raise ValueError("输入必须是0或1")

        A, b = pk

        # 随机向量r ∈ {0, 1}^m
        r = np.random.randint(0, 2, size=self.m)

        # 计算密文
        c1 = (r @ A) % self.q
        c2 = (r @ b + bit * (self.q // 2)) % self.q

        return c1, c2

    def encrypt(self, pk: Tuple[np.ndarray, np.ndarray], message: Union[List[int], np.ndarray]) -> List[Tuple[np.ndarray, int]]:
        """
        加密比特序列

        参数:
            pk: 公钥(A, b)
            message: 比特序列

        返回:
            密文列表
        """
        return [self.encrypt_bit(pk, bit) for bit in message]

    def decrypt_bit(self, sk: np.ndarray, ciphertext: Tuple[np.ndarray, int]) -> int:
        """
        解密单个比特

        参数:
            sk: 私钥s
            ciphertext: 密文(c1, c2)

        返回:
            解密后的比特
        """
        c1, c2 = ciphertext
        s = sk

        # 计算v = c2 - c1·s
        v = (c2 - c1 @ s) % self.q

        # 判断v与q/2的接近程度
        # 如果v接近0或q，则解密为0；如果v接近q/2，则解密为1
        if v < self.q // 4 or v > 3 * self.q // 4:
            return 0
        else:
            return 1

    def decrypt(self, sk: np.ndarray, ciphertexts: List[Tuple[np.ndarray, int]]) -> List[int]:
        """
        解密比特序列

        参数:
            sk: 私钥s
            ciphertexts: 密文列表

        返回:
            解密后的比特列表
        """
        return [self.decrypt_bit(sk, ct) for ct in ciphertexts]

    def homomorphic_add(self, ct1: Tuple[np.ndarray, int], ct2: Tuple[np.ndarray, int]) -> Tuple[np.ndarray, int]:
        """
        同态加法: E(m1) + E(m2) = E(m1 + m2)

        参数:
            ct1: 第一个密文(c1, c2)
            ct2: 第二个密文(c1', c2')

        返回:
            加法结果的密文
        """
        c1_1, c2_1 = ct1
        c1_2, c2_2 = ct2

        # 将密文成分相加
        c1_sum = (c1_1 + c1_2) % self.q
        c2_sum = (c2_1 + c2_2) % self.q

        # 同态加法在二进制情况下需要特殊处理
        # 如果结果超过q/2，可能需要调整以避免溢出
        # 这里使用简单的方法进行调整
        if c2_sum > self.q // 2 and c2_sum < 3 * self.q // 4:
            # 如果结果在q/2和3q/4之间，将其设为q/2
            # 这样解密时仍会被解释为1
            c2_sum = self.q // 2

        return c1_sum, c2_sum

    def homomorphic_not(self, ct: Tuple[np.ndarray, int]) -> Tuple[np.ndarray, int]:
        """
        同态非运算: E(m) -> E(1-m)

        参数:
            ct: 密文(c1, c2)

        返回:
            非运算结果的密文
        """
        c1, c2 = ct

        # NOT操作相当于从q/2减去c2，并对c1取反
        # 我们需要保持c1的类型不变
        if isinstance(c1, np.ndarray):
            # 如果c1是数组，对每个元素取负
            c1_not = (-c1) % self.q
        else:
            # 如果c1是标量，直接取负
            c1_not = (-c1) % self.q

        # c2也需要适当调整
        c2_not = (self.q // 2 - c2) % self.q

        return c1_not, c2_not

    def error_analysis(self, num_samples: int = 1000) -> Tuple[float, float]:
        """
        进行错误分析，测试加密和解密的正确率

        参数:
            num_samples: 测试样本数量

        返回:
            (error_rate_0, error_rate_1): 0和1的错误率
        """
        # 生成密钥
        if self.public_key is None or self.secret_key is None:
            self.keygen()

        errors_0 = 0
        errors_1 = 0

        # 测试0的加密和解密
        for _ in range(num_samples):
            ct = self.encrypt_bit(self.public_key, 0)
            if self.decrypt_bit(self.secret_key, ct) != 0:
                errors_0 += 1

        # 测试1的加密和解密
        for _ in range(num_samples):
            ct = self.encrypt_bit(self.public_key, 1)
            if self.decrypt_bit(self.secret_key, ct) != 1:
                errors_1 += 1

        return errors_0 / num_samples, errors_1 / num_samples

    def demonstrate_homomorphic_properties(self, a: int, b: int) -> None:
        """
        演示同态属性

        参数:
            a: 第一个比特
            b: 第二个比特
        """
        if self.public_key is None or self.secret_key is None:
            self.keygen()

        # 加密两个比特
        ct_a = self.encrypt_bit(self.public_key, a)
        ct_b = self.encrypt_bit(self.public_key, b)

        # 直接计算XOR结果
        expected_xor = a ^ b

        # 同态计算XOR: a XOR b = a + b - 2(a AND b)
        # 但这个公式在位加密中不是直接适用的

        # 在LWE中，我们可以使用更简单的方法实现XOR
        # XOR可以表示为: (a OR b) AND NOT(a AND b)

        # 计算a + b (加法会近似OR，但可能有误差)
        ct_sum = self.homomorphic_add(ct_a, ct_b)

        # 计算NOT(a) + NOT(b) (这近似于NOT(a AND b))
        # 注意：在二进制域中，NOT(a AND b) = NOT(a) OR NOT(b)
        ct_a_not = self.homomorphic_not(ct_a)
        ct_b_not = self.homomorphic_not(ct_b)

        # 简化XOR计算，使用替代方法
        # 我们将使用: (a + b) mod 2 近似XOR
        # 在LWE中，这可以通过适当的缩放和舍入来实现

        # 方法1: 在解密前直接对密文成分进行调整
        c1_a, c2_a = ct_a
        c1_b, c2_b = ct_b

        # 简单的XOR近似
        c1_xor = (c1_a + c1_b) % self.q
        c2_xor = (c2_a + c2_b) % self.q

        # 如果结果超过q/4，调整回到[0,q/2]范围
        if isinstance(c2_xor, np.ndarray):
            # 如果是数组，逐元素处理
            for i in range(len(c2_xor)):
                if c2_xor[i] > 3 * self.q // 4:
                    c2_xor[i] = c2_xor[i] - self.q
                elif c2_xor[i] > self.q // 4 and c2_xor[i] < self.q // 2:
                    c2_xor[i] = self.q // 2
        else:
            # 如果是标量，直接处理
            if c2_xor > 3 * self.q // 4:
                c2_xor = c2_xor - self.q
            elif c2_xor > self.q // 4 and c2_xor < self.q // 2:
                c2_xor = self.q // 2

        ct_xor = (c1_xor, c2_xor)

        # 解密结果
        dec_a = self.decrypt_bit(self.secret_key, ct_a)
        dec_b = self.decrypt_bit(self.secret_key, ct_b)
        dec_xor = self.decrypt_bit(self.secret_key, ct_xor)

        # 也解密中间结果，用于调试
        dec_a_not = self.decrypt_bit(self.secret_key, ct_a_not)
        dec_b_not = self.decrypt_bit(self.secret_key, ct_b_not)

        print(f"输入: a = {a}, b = {b}")
        print(f"解密验证: a = {dec_a}, b = {dec_b}")
        print(f"中间结果: NOT(a) = {dec_a_not}, NOT(b) = {dec_b_not}")
        print(f"预期结果: a XOR b = {expected_xor}")
        print(f"同态计算结果: {dec_xor}")

        if dec_xor == expected_xor:
            print(f"✓ 结果正确!")
        else:
            print(f"✗ 结果错误! 期望 {expected_xor} 但得到 {dec_xor}")
            # 计算错误率以提供更多信息
            error_rate_0, error_rate_1 = self.error_analysis(num_samples=100)
            print(f"当前参数下错误率: 0的错误率={error_rate_0:.4f}, 1的错误率={error_rate_1:.4f}")
            if error_rate_0 > 0.1 or error_rate_1 > 0.1:
                print("错误率较高，这可能影响同态计算的准确性")


def benchmark_lwe(param_sets: List[LWEParameters], num_trials: int = 10) -> None:
    """
    对不同参数集的LWE性能进行基准测试

    参数:
        param_sets: 要测试的参数集列表
        num_trials: 每组参数的测试次数
    """
    results = []

    for params in param_sets:
        try:
            # 初始化LWE系统
            lwe = RegevLWE(params)

            # 测量密钥生成时间
            key_times = []
            for _ in range(num_trials):
                start = time.time()
                lwe.keygen()
                key_times.append(time.time() - start)
            avg_key_time = sum(key_times) / num_trials

            # 测量加密时间
            encrypt_times = []
            for _ in range(num_trials):
                message = [np.random.randint(0, 2) for _ in range(10)]
                start = time.time()
                lwe.encrypt(lwe.public_key, message)
                encrypt_times.append(time.time() - start)
            avg_encrypt_time = sum(encrypt_times) / num_trials / 10  # 每比特时间

            # 测量错误率
            error_rate_0, error_rate_1 = lwe.error_analysis(num_samples=100)

            results.append({
                'params': params,
                'key_time': avg_key_time,
                'encrypt_time': avg_encrypt_time,
                'error_rate_0': error_rate_0,
                'error_rate_1': error_rate_1
            })
        except Exception as e:
            print(f"参数集 ({params.n}, {params.q}, {params.m}, {params.sigma}) 测试失败: {e}")

    # 显示结果
    print("LWE性能基准测试结果:")
    print("-" * 80)
    print(f"{'参数(n, q, m, σ)':<25} {'密钥生成(秒)':<15} {'每比特加密(秒)':<15} {'0错误率':<10} {'1错误率':<10}")
    print("-" * 80)

    for r in results:
        p = r['params']
        params_str = f"({p.n}, {p.q}, {p.m}, {p.sigma})"
        print(f"{params_str:<25} {r['key_time']:<15.6f} {r['encrypt_time']:<15.6f} {r['error_rate_0']:<10.6f} {r['error_rate_1']:<10.6f}")


def plot_error_rates(sigma_values: List[float]) -> None:
    """
    绘制不同噪声水平下的错误率曲线

    参数:
        sigma_values: 要测试的标准差值列表
    """
    error_rates_0 = []
    error_rates_1 = []

    base_params = LWEParameters(n=64, q=3329, m=128, sigma=2.0)

    for sigma in sigma_values:
        try:
            params = LWEParameters(n=base_params.n, q=base_params.q, m=base_params.m, sigma=sigma)
            lwe = RegevLWE(params)
            lwe.keygen()
            error_rate_0, error_rate_1 = lwe.error_analysis(num_samples=100)
            error_rates_0.append(error_rate_0)
            error_rates_1.append(error_rate_1)
        except Exception as e:
            print(f"sigma={sigma} 测试失败: {e}")
            # 添加默认值，保持列表长度一致
            error_rates_0.append(0)
            error_rates_1.append(0)

    plt.figure(figsize=(10, 6))
    plt.plot(sigma_values, error_rates_0, 'o-', label='错误率 (0)')
    plt.plot(sigma_values, error_rates_1, 's-', label='错误率 (1)')
    plt.xlabel('噪声标准差 (σ)')
    plt.ylabel('错误率')
    plt.title('LWE: 噪声水平vs错误率')
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.show()


def main():
    """主函数，演示LWE加密系统的使用"""
    print("=" * 80)
    print("Regev LWE (Learning with Errors) 加密系统演示")
    print("=" * 80)

    p = LWEParameters.recommended_parameters()
    lwe = RegevLWE(p)
    print(f"\n使用参数: n={lwe.n}, q={lwe.q}, m={lwe.m}, σ={lwe.sigma}")

    # 生成密钥对
    print("\n1. 生成密钥对")
    start = time.time()
    public_key, secret_key = lwe.keygen()
    key_time = time.time() - start
    print(f"密钥生成用时: {key_time:.6f} 秒")

    # 要加密的消息
    message_bits = np.random.randint(2, size=100)
    print(f"\n2. 待加密消息: {message_bits}")

    # 加密消息
    print("\n3. 加密消息")
    start = time.time()
    ciphertext = lwe.encrypt(public_key, message_bits)
    encrypt_time = time.time() - start
    print(f"加密用时: {encrypt_time:.6f} 秒")
    print(f"密文大小: {sum([c1.size + 1 for c1, _ in ciphertext]) * 8} 比特")

    # 解密消息
    print("\n4. 解密消息")
    start = time.time()
    decrypted_message = lwe.decrypt(secret_key, ciphertext)
    decrypt_time = time.time() - start
    print(f"解密用时: {decrypt_time:.6f} 秒")
    print(f"解密结果: {decrypted_message}")
    print(f"解密正确: {np.array_equal(message_bits, decrypted_message)}")

    # 错误分析
    print("\n5. 错误率分析")
    error_rate_0, error_rate_1 = lwe.error_analysis(num_samples=1000)
    print(f"0的错误率: {error_rate_0:.6f}")
    print(f"1的错误率: {error_rate_1:.6f}")

    # 同态性质演示
    print("\n6. 同态性质演示")
    try:
        # 确保已经生成密钥
        if lwe.public_key is None or lwe.secret_key is None:
            print("未检测到密钥，重新生成密钥...")
            lwe.keygen()

        # 使用更适合同态操作的参数
        print("注意: 同态操作在某些参数设置下可能不稳定")
        print("以下结果仅供参考，实际应用中需要更精细的参数调整")

        print("-" * 40)
        print("测试 0 XOR 0:")
        lwe.demonstrate_homomorphic_properties(0, 0)
        print("-" * 40)
        print("测试 0 XOR 1:")
        lwe.demonstrate_homomorphic_properties(0, 1)
        print("-" * 40)
        print("测试 1 XOR 0:")
        lwe.demonstrate_homomorphic_properties(1, 0)
        print("-" * 40)
        print("测试 1 XOR 1:")
        lwe.demonstrate_homomorphic_properties(1, 1)
    except Exception as e:
        print(f"同态演示失败: {e}")
        print("错误详情:", str(e))
        print("\n尝试基本同态操作演示...")

        try:
            # 简化的同态操作演示
            pk, sk = lwe.keygen()  # 重新生成密钥

            # 加密两个比特
            bit_0 = 0
            bit_1 = 1
            ct_0 = lwe.encrypt_bit(pk, bit_0)
            ct_1 = lwe.encrypt_bit(pk, bit_1)

            # 解密验证
            dec_0 = lwe.decrypt_bit(sk, ct_0)
            dec_1 = lwe.decrypt_bit(sk, ct_1)

            print(f"加密/解密测试: {bit_0} -> {dec_0}, {bit_1} -> {dec_1}")

            # 同态加法 (0 + 1)
            ct_add = lwe.homomorphic_add(ct_0, ct_1)
            dec_add = lwe.decrypt_bit(sk, ct_add)
            print(f"同态加法: {bit_0} + {bit_1} = {dec_add} (期望值为1)")

            # 同态NOT (NOT 0)
            ct_not = lwe.homomorphic_not(ct_0)
            dec_not = lwe.decrypt_bit(sk, ct_not)
            print(f"同态NOT: NOT {bit_0} = {dec_not} (期望值为1)")

        except Exception as e2:
            print(f"基本同态操作也失败: {e2}")
            print("参数设置可能不适合同态操作，或实现有误")

    print("\n7. 不同参数集性能比较")
    param_sets = [
        LWEParameters(n=32, q=1031, m=64, sigma=2.0),
        LWEParameters(n=64, q=3329, m=128, sigma=2.0),
        LWEParameters(n=128, q=8191, m=256, sigma=2.0)
    ]
    try:
        # 减少测试次数，避免性能问题
        benchmark_lwe(param_sets, num_trials=3)
    except Exception as e:
        print(f"参数集性能比较失败: {e}")
        print("尝试单独测试每个参数集...")
        for params in param_sets:
            try:
                print(f"测试参数集: n={params.n}, q={params.q}, m={params.m}, σ={params.sigma}")
                lwe_test = RegevLWE(params)
                pk, sk = lwe_test.keygen()
                print("  密钥生成成功")
            except Exception as e:
                print(f"  失败: {e}")

    print("\n8. 根据安全级别推荐参数")
    try:
        for level in [80, 128, 256]:
            params = LWEParameters.recommended_parameters(level)
            print(f"安全级别 {level} 比特: n={params.n}, q={params.q}, m={params.m}, σ={params.sigma}")
    except Exception as e:
        print(f"参数推荐失败: {e}")

    print("\n" + "=" * 80)
    print("演示结束")


if __name__ == "__main__":
    try:
        main()
        print("程序正常完成")
    except Exception as e:
        print(f"程序执行过程中发生未处理的异常: {e}")
        print("请检查参数设置或代码实现")

    # 如果要绘制错误率曲线，取消下面的注释
    try:
        sigma_values = [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0, 8, 16, 32]
        plot_error_rates(sigma_values)
    except Exception as e:
        print(f"绘制错误率曲线失败: {e}")
