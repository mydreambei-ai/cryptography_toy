"""
椭圆曲线算法实现

椭圆曲线形式: y^2 = x^3 + a*x + b

本模块提供了椭圆曲线上的点运算和相关操作，支持以下功能:
- 点加法、点倍乘、点数乘
- 有限域和有理数域上的椭圆曲线
- 雅可比坐标表示
- 点的压缩和恢复

参考资料:
- Guide to Elliptic Curve Cryptography (Hankerson, Menezes, Vanstone)
- SEC 1: Elliptic Curve Cryptography (www.secg.org)
"""

from fractions import Fraction
from typing import Union, Optional, Tuple, Any
import secrets

from common import cipolla
from galois import GF, GFItem


class Point:
    """
    椭圆曲线上的点，支持仿射坐标和雅可比投影坐标

    属性:
        x: x坐标
        y: y坐标
        z: 投影坐标的z分量，仿射坐标时为1，无穷远点时为0
    """

    def __init__(self, x: Any, y: Any, z: Any = 1):
        """
        初始化椭圆曲线上的点

        参数:
            x: x坐标
            y: y坐标
            z: 投影坐标的z分量，默认为1（仿射坐标）
        """
        self.x = x
        self.y = y
        self.z = z

    def is_infinity(self) -> bool:
        """判断点是否为无穷远点"""
        return self.z == 0

    def to_affine(self) -> 'Point':
        """将点从雅可比坐标转换为仿射坐标"""
        if self.is_infinity():
            return self

        # 已经是仿射坐标
        if self.z == 1:
            return self

        # 进行坐标转换: (X/Z^2, Y/Z^3)
        x_affine = self.x / (self.z ** 2)
        y_affine = self.y / (self.z ** 3)
        return Point(x_affine, y_affine, 1)

    def __repr__(self) -> str:
        """返回点的字符串表示"""
        if self.is_infinity():
            return "Point(∞)"
        if self.z == 1:
            return f"Point({self.x}, {self.y})"
        return f"Point({self.x}, {self.y}, {self.z})"

    def __eq__(self, other: Any) -> bool:
        """
        判断两个点是否相等

        在雅可比坐标系中，(X1:Y1:Z1)与(X2:Y2:Z2)相等当且仅当:
        X1*Z2^2 = X2*Z1^2 且 Y1*Z2^3 = Y2*Z1^3
        """
        if not isinstance(other, Point):
            return False

        if self.is_infinity() and other.is_infinity():
            return True

        if self.is_infinity() or other.is_infinity():
            return False

        # 简单情况：两点都是仿射坐标
        if self.z == 1 and other.z == 1:
            return self.x == other.x and self.y == other.y

        # 一般情况：使用投影坐标等价性检查
        return (self.x * other.z**2 == other.x * self.z**2 and
                self.y * other.z**3 == other.y * self.z**3)


# 定义无穷远点作为椭圆曲线的零元素
InfinityPoint = Point(0, 1, 0)


class EllipticCurve:
    """
    椭圆曲线 y^2 = x^3 + a*x + b

    支持有限域和有理数域上的椭圆曲线操作
    """

    def __init__(self, a: Union[int, GFItem], b: Union[int, GFItem], p: Optional[int] = None, order: Optional[int] = None, skip_primality_check: bool = False):
        """
        初始化椭圆曲线

        参数:
            a: 曲线参数a
            b: 曲线参数b
            p: 有限域的模数（素数），若为None则使用有理数域
            order: 椭圆曲线群的阶（元素个数），若已知可提供
            skip_primality_check: 是否跳过素数检查，对于已知的标准曲线可设为True

        抛出:
            ValueError: 若曲线是奇异的（判别式为0）
        """
        self.a = a
        self.b = b
        self.order = order
        self.p = p

        # 有限域或有理数域
        if p:
            if skip_primality_check:
                # 跳过素数检查，直接创建有限域
                self.gf = GF(p, skip_primality_check=True)
            else:
                self.gf = GF(p)
            # 确保a和b是有限域中的元素
            if not isinstance(a, GFItem):
                self.a = self.gf(a).item
            if not isinstance(b, GFItem):
                self.b = self.gf(b).item
        else:
            self.gf = None

        # 检查曲线是否奇异
        if self.is_singular():
            raise ValueError(f"椭圆曲线 y^2 = x^3 + {a}x + {b} 是奇异的")

        # 缓存常用值以提高性能
        self._infinity = InfinityPoint
        self._cached_points = {}

    def __repr__(self) -> str:
        """返回椭圆曲线的字符串表示"""
        s = "y^2 = x^3"

        if self.a != 0:
            sign = "+" if self.a > 0 else ""
            s = f"{s} {sign}{self.a}x"

        if self.b != 0:
            sign = "+" if self.b > 0 else ""
            s = f"{s} {sign}{self.b}"

        if self.p:
            s = f"{s} over GF({self.p})"

        return s

    def is_singular(self) -> bool:
        """
        检查曲线是否奇异

        当判别式 4a^3 + 27b^2 = 0 时，曲线是奇异的
        """
        discriminant = 4 * self.a**3 + 27 * self.b**2

        if self.gf:
            return self.gf(discriminant).item == 0
        else:
            return discriminant == 0

    def __call__(self, px: Union[int, GFItem], py: Union[int, GFItem]) -> Point:
        """
        创建曲线上的点，并验证点是否在曲线上

        参数:
            px: x坐标
            py: y坐标

        返回:
            曲线上的点

        抛出:
            ValueError: 若点不在曲线上
        """
        p = Point(px, py)
        if p not in self:
            raise ValueError(f"点 {p} 不在曲线 {self} 上")
        return p

    def double_point(self, point: Point) -> Point:
        """
        计算点的二倍点 [2]P

        参数:
            point: 要倍乘的点

        返回:
            倍乘结果 [2]P
        """
        # 边界情况
        if point.is_infinity():
            return InfinityPoint

        x, y = point.x, point.y

        # 若y坐标为0，则切线垂直于x轴，二倍点为无穷远点
        if y == 0:
            return InfinityPoint

        # 计算切线斜率 m = (3x^2 + a) / (2y)
        if self.gf:
            x_squared = self.gf(x)**2
            numerator = 3 * x_squared + self.gf(self.a)
            denominator = 2 * self.gf(y)
            m = numerator / denominator

            # 计算新点坐标
            x3 = m**2 - 2 * self.gf(x)
            y3 = m * (self.gf(x) - x3) - self.gf(y)

            return Point(x3.item, y3.item)
        else:
            # 有理数域上的计算
            m = Fraction((3 * x**2 + self.a), (2 * y))
            x3 = m**2 - 2 * point.x
            y3 = m * (point.x - x3) - point.y

            return Point(Fraction(x3), Fraction(y3))

    def add_point(self, p1: Point, p2: Point) -> Point:
        """
        计算两个点的和 P1 + P2

        参数:
            p1: 第一个点
            p2: 第二个点

        返回:
            两点之和 P1 + P2
        """
        # 处理无穷远点情况
        if p1.is_infinity():
            return p2
        if p2.is_infinity():
            return p1

        # 若两点x坐标相同
        if p1.x == p2.x:
            # 若y坐标相同，则是倍点
            if p1.y == p2.y:
                return self.double_point(p1)
            # 若y坐标相反，则和为无穷远点
            else:
                return InfinityPoint

        # 计算斜率 m = (y2 - y1) / (x2 - x1)
        if self.gf:
            # 有限域上的计算
            x1, y1 = self.gf(p1.x), self.gf(p1.y)
            x2, y2 = self.gf(p2.x), self.gf(p2.y)

            m = (y2 - y1) / (x2 - x1)

            # 计算新点坐标
            x3 = m**2 - x1 - x2
            y3 = m * (x1 - x3) - y1

            return Point(x3.item, y3.item)
        else:
            # 有理数域上的计算
            m = Fraction((p2.y - p1.y), (p2.x - p1.x))
            x3 = m**2 - p1.x - p2.x
            y3 = m * (p1.x - x3) - p1.y

            return Point(Fraction(x3), Fraction(y3))

    def mul_point(self, point: Point, n: int) -> Point:
        """
        计算点的数乘 [n]P

        使用双倍加算法（Double-and-Add）计算数乘，复杂度为 O(log n)

        参数:
            point: 基点
            n: 乘数

        返回:
            数乘结果 [n]P

        抛出:
            ValueError: 若n为负数
        """
        if n < 0:
            raise ValueError("乘数必须是非负整数")

        if n == 0 or point.is_infinity():
            return InfinityPoint

        if n == 1:
            return point

        # 使用窗口化方法可提高性能
        # 对于大乘数，预计算一些点可以减少计算量
        if n > 16:
            return self._mul_point_windowed(point, n)

        # 标准双倍加算法
        result = InfinityPoint
        addend = point

        while n > 0:
            if n & 1:  # 如果最低位为1
                result = self.add_point(result, addend)
            addend = self.double_point(addend)
            n >>= 1  # 右移一位

        return result

    def _mul_point_windowed(self, point: Point, n: int, window_size: int = 4) -> Point:
        """
        使用窗口化方法实现的点乘，适用于大数乘法

        参数:
            point: 基点
            n: 乘数
            window_size: 窗口大小（推荐4或5）

        返回:
            数乘结果 [n]P
        """
        # 预计算点表
        precomp = [InfinityPoint] * (1 << window_size)
        precomp[1] = point

        for i in range(2, 1 << window_size):
            precomp[i] = self.add_point(precomp[i-1], point)

        # 窗口化处理乘数
        result = InfinityPoint
        i = n.bit_length()

        while i > 0:
            if i < window_size:
                # 处理最后不足window_size的位
                for j in range(i-1, -1, -1):
                    result = self.double_point(result)
                    if (n >> j) & 1:
                        result = self.add_point(result, point)
                break

            # 处理一个完整窗口
            for _ in range(window_size):
                result = self.double_point(result)

            # 提取当前窗口的位
            window_bits = (n >> (i - window_size)) & ((1 << window_size) - 1)

            if window_bits > 0:
                result = self.add_point(result, precomp[window_bits])

            i -= window_size

        return result

    def neg_point(self, p: Point) -> Point:
        """
        计算点的负元 -P

        椭圆曲线上点(x,y)的负元是(x,-y)

        参数:
            p: 输入点

        返回:
            点的负元 -P
        """
        if p.is_infinity():
            return InfinityPoint

        if self.gf:
            return Point(p.x, (self.p - p.y) % self.p)
        else:
            return Point(p.x, -p.y)

    def sub_point(self, p1: Point, p2: Point) -> Point:
        """
        计算两点之差 P1 - P2

        参数:
            p1: 第一个点
            p2: 第二个点

        返回:
            两点之差 P1 - P2
        """
        return self.add_point(p1, self.neg_point(p2))

    def compute_slope(self, p1: Point, p2: Point) -> Union[Fraction, GFItem]:
        """
        计算两点间的斜率

        参数:
            p1: 第一个点
            p2: 第二个点

        返回:
            两点间的斜率

        抛出:
            ValueError: 若两点x坐标相同（斜率不存在）
        """
        if p1.x == p2.x:
            raise ValueError("两点x坐标相同，斜率不存在")

        if self.gf:
            return (self.gf(p2.y) - self.gf(p1.y)) / (self.gf(p2.x) - self.gf(p1.x))
        else:
            return Fraction((p2.y - p1.y), (p2.x - p1.x))

    def y_recover(self, x: int, is_even: bool = True) -> Optional[Point]:
        """
        从x坐标恢复点的y坐标（点的解压缩）

        在有限域上，每个有效的x坐标对应两个可能的y值

        参数:
            x: x坐标
            is_even: 如果为True，选择较小的y值；否则选择较大的y值

        返回:
            恢复的点，如果x无对应的有效点则返回None
        """
        if not self.p:
            raise ValueError("只支持有限域上的点恢复")

        x = x % self.p

        # 计算 y^2 = x^3 + ax + b
        y_squared = (x**3 + self.a * x + self.b) % self.p

        # 使用Cipolla算法计算模平方根
        y = cipolla(y_squared, self.p)

        if y is None:
            return None

        # 确保y是最小的解或最大的解
        y2 = self.p - y

        if is_even:
            # 在有限域中，"偶数"通常指二次剩余
            y_result = min(y, y2)
        else:
            y_result = max(y, y2)

        return Point(x, y_result)

    def compress_point(self, point: Point) -> Tuple[int, bool]:
        """
        压缩曲线上的点

        使用x坐标和y坐标的奇偶性表示点

        参数:
            point: 要压缩的点

        返回:
            (x坐标, y坐标是否为较大值)
        """
        if point.is_infinity():
            raise ValueError("无穷远点不能被压缩")

        if not self.p:
            raise ValueError("只支持有限域上的点压缩")

        return point.x, (point.y > self.p // 2)

    def random_point(self) -> Point:
        """
        生成曲线上的随机点

        返回:
            曲线上的随机点

        抛出:
            ValueError: 若在有理数域上或无法找到有效点
        """
        if not self.p:
            raise ValueError("只支持在有限域上生成随机点")

        # 随机选择x坐标，计算对应的y^2
        max_attempts = 100
        for _ in range(max_attempts):
            x = secrets.randbelow(self.p)
            y_squared = (x**3 + self.a * x + self.b) % self.p

            # 使用Cipolla算法计算y
            y = cipolla(y_squared, self.p)

            if y is not None:
                # 随机选择两个可能的y值之一
                if secrets.randbelow(2):
                    y = self.p - y
                return Point(x, y)

        raise ValueError("无法在合理尝试次数内找到曲线上的有效点")

    def __contains__(self, p: Point) -> bool:
        """
        检查点是否在曲线上

        参数:
            p: 要检查的点

        返回:
            如果点在曲线上则为True，否则为False
        """
        # 无穷远点总是在曲线上
        if p.is_infinity():
            return True

        # 检查点是否满足曲线方程 y^2 = x^3 + ax + b
        if self.gf:
            left = self.gf(p.y)**2
            right = self.gf(p.x)**3 + self.gf(self.a) * self.gf(p.x) + self.gf(self.b)
            return left == right
        else:
            return p.y**2 == p.x**3 + self.a * p.x + self.b


def demo_elliptic_curve():
    """演示椭圆曲线上的各种操作"""
    print("=== 椭圆曲线演示 ===")

    # 在有限域GF(13)上创建曲线 y^2 = x^3 + 2x + 3
    print("\n1. 在GF(13)上创建椭圆曲线 y^2 = x^3 + 2x + 3")
    E = EllipticCurve(2, 3, 13)
    print(f"曲线方程: {E}")

    # 创建曲线上的点
    p = E(6, 6)
    print(f"\n2. 在曲线上创建点 P = {p}")

    # 点的倍乘
    p2 = E.double_point(p)
    print(f"\n3. 点的倍乘 [2]P = {p2}")

    # 点的加法
    p3 = E.add_point(p, p2)
    print(f"   点的加法 P + [2]P = {p3}")

    # 点的数乘
    p4 = E.mul_point(p, 4)
    print(f"   点的数乘 [4]P = {p4}")

    # 验证点运算性质
    print("\n4. 验证点运算性质:")
    p5 = E.add_point(p, p4)
    p6 = E.mul_point(p, 6)

    print(f"   [6]P = [2]P + [4]P: {p6 == E.add_point(p2, p4)}")
    print(f"   [6]P = [2](P + [2]P): {p6 == E.double_point(p3)}")
    print(f"   [6]P = P + [5]P: {p6 == E.add_point(p, p5)}")

    # 点的压缩与恢复
    print("\n5. 点的压缩与恢复:")
    x, is_larger = E.compress_point(p)
    print(f"   压缩点 P 得到: x={x}, is_larger={is_larger}")

    recovered = E.y_recover(x, not is_larger)
    print(f"   从压缩信息恢复得到: {recovered}")
    print(f"   恢复的点等于原点: {recovered == p}")

    # 随机点生成
    print("\n6. 生成曲线上的随机点:")
    random_point = E.random_point()
    print(f"   随机点: {random_point}")
    print(f"   验证点在曲线上: {random_point in E}")


if __name__ == "__main__":
    demo_elliptic_curve()
