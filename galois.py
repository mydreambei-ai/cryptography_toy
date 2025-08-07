
"""
Galois 有限域 (GF(p)) 的实现

这个模块提供了在有限域上进行算术运算的类和函数。
支持 GF(p) 素数域的加、减、乘、除和幂运算。

示例:
    F = GF(17)  # 创建 GF(17) 有限域
    a = F(7)    # 创建域中的元素
    b = F(8)
    c = a + b   # 执行域中的算术运算
"""

from typing import Union, Tuple, List, Any
import random


class GF:
    """
    表示素数域 GF(p) 的类，其中 p 是素数

    属性:
        p: 有限域的模数 (必须是素数)
        zero: 域中的零元素
        one: 域中的单位元素
    """

    def __init__(self, p: int, skip_primality_check: bool = False):
        """
        初始化素数域 GF(p)

        参数:
            p: 有限域的模数 (必须是素数)
            skip_primality_check: 是否跳过素数检查，对于大素数可提高性能

        抛出:
            ValueError: 如果 p 不是素数且未设置跳过检查
        """
        if not skip_primality_check and not self.is_prime(p):
            raise ValueError(f"{p} 不是素数，请使用素数作为模数")
        self.p = p
        self._zero = None  # 延迟初始化
        self._one = None   # 延迟初始化

    @property
    def zero(self) -> 'GFItem':
        """返回域中的零元素"""
        if self._zero is None:
            self._zero = GFItem(0, self)
        return self._zero

    @property
    def one(self) -> 'GFItem':
        """返回域中的单位元素"""
        if self._one is None:
            self._one = GFItem(1, self)
        return self._one

    @staticmethod
    def is_prime(n: int) -> bool:
        """
        检查一个数是否为素数

        参数:
            n: 要检查的整数

        返回:
            如果 n 是素数则为 True，否则为 False
        """
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0 or n % 3 == 0:
            return False

        # 对于小数使用试除法
        if n < 10000:
            i = 5
            while i * i <= n:
                if n % i == 0 or n % (i + 2) == 0:
                    return False
                i += 6
            return True

        # 对于大数使用Miller-Rabin素性测试
        # 执行几轮测试以获得高概率的结果
        for _ in range(5):  # 5轮测试，错误概率极低
            a = random.randint(2, n - 2)
            # 计算 a^(n-1) mod n
            if pow(a, n - 1, n) != 1:
                return False
        return True  # 可能是素数（高概率）

    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        """
        计算扩展欧几里得算法: ax + by = gcd(a,b)

        参数:
            a, b: 两个整数

        返回:
            (gcd, x, y): 满足 ax + by = gcd(a,b) 的整数元组
        """
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def inverse(self, a: Union[int, 'GFItem']) -> 'GFItem':
        """
        计算元素在有限域中的乘法逆元

        参数:
            a: 要求逆元的元素

        返回:
            a 的乘法逆元

        抛出:
            ValueError: 如果元素没有逆元
        """
        if isinstance(a, GFItem):
            a = a.item

        # 处理边界情况
        if a == 0:
            raise ValueError(f"0 在 GF({self.p}) 中没有逆元")

        # 使用费马小定理计算逆元（如果 p 是素数）
        if self.is_prime(self.p):
            return GFItem(pow(a, self.p - 2, self.p), self)

        # 如果不确定 p 是素数，使用扩展欧几里得算法
        gcd, x, y = self.extended_gcd(a, self.p)
        if gcd != 1:
            raise ValueError(f"{a} 在 GF({self.p}) 中没有逆元")
        return GFItem(x % self.p, self)

    def __eq__(self, other: Any) -> bool:
        """
        检查两个有限域是否相等

        参数:
            other: 要比较的对象

        返回:
            如果两个域相等则为 True，否则为 False
        """
        if not isinstance(other, GF):
            return False
        return self.p == other.p

    def __hash__(self) -> int:
        """使 GF 对象可哈希，以便用作字典键"""
        return hash(('GF', self.p))

    def __call__(self, item: int) -> 'GFItem':
        """
        将整数转换为该有限域中的元素

        参数:
            item: 要转换的整数

        返回:
            该有限域中的对应元素
        """
        return GFItem(item, self)

    def __repr__(self) -> str:
        """返回有限域的字符串表示"""
        return f"GF({self.p})"

    def random_element(self) -> 'GFItem':
        """
        返回域中的随机元素

        返回:
            该有限域中的随机元素
        """
        return GFItem(random.randint(0, self.p - 1), self)

    def elements(self) -> List['GFItem']:
        """
        返回域中所有元素的列表

        返回:
            包含域中所有元素的列表
        """
        return [GFItem(i, self) for i in range(self.p)]

    def order(self) -> int:
        """
        返回有限域的阶（元素个数）

        返回:
            域中元素的个数
        """
        return self.p


class GFItem:
    """
    表示有限域 GF(p) 中的元素

    属性:
        item: 元素的整数值
        parent: 元素所属的有限域
    """

    def __init__(self, item: int, parent: GF):
        """
        初始化有限域中的元素

        参数:
            item: 元素的整数值
            parent: 元素所属的有限域
        """
        self.item = item % parent.p
        self.parent = parent

    def __repr__(self) -> str:
        """返回元素的字符串表示"""
        return f"GF({self.parent.p})({self.item})"

    def __int__(self) -> int:
        """将元素转换为整数"""
        return self.item

    def __eq__(self, other: Any) -> bool:
        """
        检查两个元素是否相等

        参数:
            other: 要比较的对象

        返回:
            如果两个元素相等则为 True，否则为 False
        """
        if not isinstance(other, GFItem):
            if isinstance(other, int):
                return self.item == (other % self.parent.p)
            return False
        return (self.parent == other.parent) and (self.item == other.item)

    def __hash__(self) -> int:
        """使 GFItem 对象可哈希，以便用作字典键"""
        return hash((self.item, self.parent))

    def _check_compatibility(self, other: Any) -> None:
        """
        检查两个元素是否属于同一个域

        参数:
            other: 要检查的元素

        抛出:
            TypeError: 如果 other 不是 GFItem
            ValueError: 如果两个元素不在同一个域中
        """
        if not isinstance(other, GFItem):
            raise TypeError(f"不支持与 {type(other)} 类型的操作")
        if self.parent != other.parent:
            raise ValueError(f"元素必须在同一个域中: {self.parent} != {other.parent}")

    def __add__(self, other: Union['GFItem', int]) -> 'GFItem':
        """
        有限域加法

        参数:
            other: 要加的元素或整数

        返回:
            加法结果
        """
        if isinstance(other, int):
            other = GFItem(other, self.parent)
        self._check_compatibility(other)
        item = (self.item + other.item) % self.parent.p
        return GFItem(item, self.parent)

    def __radd__(self, other: int) -> 'GFItem':
        """
        支持整数加 GFItem

        参数:
            other: 整数

        返回:
            加法结果
        """
        return self.__add__(other)

    def __mul__(self, other: Union['GFItem', int]) -> 'GFItem':
        """
        有限域乘法

        参数:
            other: 要乘的元素或整数

        返回:
            乘法结果
        """
        if isinstance(other, int):
            other = GFItem(other, self.parent)
        self._check_compatibility(other)
        item = (self.item * other.item) % self.parent.p
        return GFItem(item, self.parent)

    def __rmul__(self, other: int) -> 'GFItem':
        """
        支持整数乘 GFItem

        参数:
            other: 整数

        返回:
            乘法结果
        """
        return self.__mul__(other)

    def __sub__(self, other: Union['GFItem', int]) -> 'GFItem':
        """
        有限域减法

        参数:
            other: 要减的元素或整数

        返回:
            减法结果
        """
        if isinstance(other, int):
            other = GFItem(other, self.parent)
        self._check_compatibility(other)
        item = (self.item - other.item) % self.parent.p
        return GFItem(item, self.parent)

    def __rsub__(self, other: int) -> 'GFItem':
        """
        支持整数减 GFItem

        参数:
            other: 整数

        返回:
            减法结果
        """
        return GFItem(other, self.parent) - self

    def __truediv__(self, other: Union['GFItem', int]) -> 'GFItem':
        """
        有限域除法

        参数:
            other: 除数

        返回:
            除法结果

        抛出:
            ZeroDivisionError: 如果除数为零
        """
        if isinstance(other, int):
            other = GFItem(other, self.parent)
        self._check_compatibility(other)
        if other.item == 0:
            raise ZeroDivisionError("除数不能为零")
        return self * (~other)

    def __rtruediv__(self, other: int) -> 'GFItem':
        """
        支持整数除以 GFItem

        参数:
            other: 整数

        返回:
            除法结果
        """
        return GFItem(other, self.parent) / self

    def __invert__(self) -> 'GFItem':
        """
        计算元素的乘法逆元

        返回:
            乘法逆元

        抛出:
            ZeroDivisionError: 如果元素为零
        """
        if self.item == 0:
            raise ZeroDivisionError(f"0 在 GF({self.parent.p}) 中没有逆元")
        return self.parent.inverse(self.item)

    def __pow__(self, exponent: Union['GFItem', int]) -> 'GFItem':
        """
        有限域幂运算

        参数:
            exponent: 指数

        返回:
            幂运算结果
        """
        if isinstance(exponent, GFItem):
            # 如果指数是域中元素，我们需要在模 p-1 下进行运算
            # 根据费马小定理 a^(p-1) ≡ 1 (mod p)
            exponent = exponent.item % (self.parent.p - 1)
        item = pow(self.item, exponent, self.parent.p)
        return GFItem(item, self.parent)

    def __neg__(self) -> 'GFItem':
        """
        返回元素的加法逆元

        返回:
            加法逆元
        """
        return GFItem(-self.item, self.parent)

    def is_zero(self) -> bool:
        """
        检查元素是否为零

        返回:
            如果元素为零则为 True，否则为 False
        """
        return self.item == 0

    def is_one(self) -> bool:
        """
        检查元素是否为一

        返回:
            如果元素为一则为 True，否则为 False
        """
        return self.item == 1

    def order(self) -> int:
        """
        计算元素的阶（使得 a^n = 1 的最小正整数 n）

        返回:
            元素的阶
        """
        if self.item == 0:
            raise ValueError("零元素没有阶")

        # 根据拉格朗日定理，元素的阶必须整除 p-1
        n = self.parent.p - 1
        factors = []

        # 计算 p-1 的质因数
        d = 2
        while d * d <= n:
            while n % d == 0:
                factors.append(d)
                n //= d
            d += 1
        if n > 1:
            factors.append(n)

        # 计算不同的质因数
        distinct_factors = list(set(factors))

        # 计算元素的阶
        order = self.parent.p - 1
        for factor in distinct_factors:
            potential_order = order // factor
            if pow(self.item, potential_order, self.parent.p) == 1:
                order = potential_order

        return order


def demo_galois_field():
    """演示 Galois 有限域的使用"""
    print("=== Galois 有限域 (GF(p)) 演示 ===\n")

    # 创建有限域 GF(17)
    print("创建有限域 GF(17):")
    F = GF(17)
    print(f"F = {F}")

    # 创建元素
    a = F(7)
    b = F(8)
    print(f"a = {a}")
    print(f"b = {b}")

    # 基本算术运算
    print("\n基本算术运算:")
    print(f"a + b = {a + b}")
    print(f"a - b = {a - b}")
    print(f"a * b = {a * b}")
    print(f"a / b = {a / b}")
    print(f"a^3 = {a**3}")
    print(f"-a = {-a}")
    print(f"1/a = {~a}")

    # 域的性质
    print("\n域的属性:")
    print(f"零元素: {F.zero}")
    print(f"单位元素: {F.one}")
    print(f"域的阶: {F.order()}")

    # 元素的阶
    print(f"\na 的阶: {a.order()}")
    print(f"b 的阶: {b.order()}")

    # 随机元素
    print("\n随机元素:")
    r = F.random_element()
    print(f"随机元素 r = {r}")

    # 验证域的运算满足的性质
    print("\n验证运算性质:")
    c = F(3)
    print(f"(a + b) + c = {(a + b) + c}")
    print(f"a + (b + c) = {a + (b + c)}")
    print(f"(a * b) * c = {(a * b) * c}")
    print(f"a * (b * c) = {a * (b * c)}")
    print(f"a * (b + c) = {a * (b + c)}")
    print(f"a * b + a * c = {a * b + a * c}")

    # 验证逆元
    print("\n验证逆元:")
    a_inv = ~a
    print(f"a * (1/a) = {a * a_inv}")

    # 与整数的操作
    print("\n与整数的操作:")
    print(f"a + 5 = {a + 5}")
    print(f"5 + a = {5 + a}")
    print(f"a * 5 = {a * 5}")
    print(f"5 * a = {5 * a}")
    print(f"a - 5 = {a - 5}")
    print(f"5 - a = {5 - a}")
    print(f"a / 5 = {a / 5}")
    print(f"5 / a = {5 / a}")


if __name__ == "__main__":
    demo_galois_field()
