from fractions import Fraction
from galois import GF, GFItem
from common import cipolla


class Point:
    def __init__(self, x, y, z=1):
        self.x = x
        self.y = y
        self.z = z

    def __repr__(self) -> str:
        return f"Point({self.x}, {self.y}, {self.z})"

    def __eq__(self, value) -> bool:
        return self.x == value.x and self.y == value.y and self.z == value.z

InfinityPoint = Point(0, 1, 0)

class EllipticCurve:
    def __init__(self, a, b, p=None, order=None):
        self.a = a
        self.b = b
        self.order = order
        self.p = p
        if p:
            self.gf = GF(p)
        else:
            self.gf = None
        if self.is_singular():
            raise ValueError("EllipticCurve is singular")

    def __repr__(self) -> str:
        s = "y^2=x^3"
        if self.a < 0:
            s = f"{s}{self.a}*x"
        elif self.a == 0:
            pass
        else:
            s = f"{s}+{self.a}*x"

        if self.b < 0:
            s = f"{s}{self.b}"
        elif self.b == 0:
            pass
        else:
            s = f"{s}+{self.b}"
        return s

    def is_singular(self):
        o = 4*self.a**3 + 27*self.b**2
        if self.gf:
            return self.gf(o).item == 0
        else:
            return o==0
        pass

    def __call__(self, px, py) -> Point:
        p = Point(px, py)
        if p not in self:
            raise ValueError(f"{p} not in {self}")
        return p

    def double_point(self, point: Point):
        x, y = point.x, point.y
        if point == InfinityPoint:
            return InfinityPoint
        if y == 0:
            return InfinityPoint
        m  = Fraction((3*x**2 + self.a), (2*y))
        x3 = m**2 -2 * point.x
        y3 = m*(point.x-x3) - point.y
        if self.gf:
            x3 = Fraction(x3)
            y3 = Fraction(y3)
            px: GFItem = self.gf(x3.numerator) / self.gf(x3.denominator)
            py: GFItem = self.gf(y3.numerator) / self.gf(y3.denominator)
            return Point(px.item, py.item)
        else:
            return Point(Fraction(x3), Fraction(y3))

    def mul_point(self, point: Point, n:int) -> Point:
        c = point
        b = InfinityPoint
        while n != 0 :
            if n & 1:
                n = n -1
                b = self.add_point(b, c)
            else:
                c = self.double_point(c)
                n = n // 2
        return b


    def add_point(self, p1: Point, p2: Point):
        if p1 == InfinityPoint:
            return p2
        if p2 == InfinityPoint:
            return p1

        if p1.x == p2.x:
            if p1.y == p2.y:
                return self.double_point(p1)
            else:
                return InfinityPoint

        m = self.scope(p1, p2)
        x3 = m**2 - p1.x - p2.x

        y3 = m * (p1.x-x3) - p1.y
        if self.gf:
            x3 = Fraction(x3)
            y3 = Fraction(y3)
            px: GFItem = self.gf(x3.numerator) / self.gf(x3.denominator)
            py: GFItem = self.gf(y3.numerator) / self.gf(y3.denominator)
            return Point(px.item, py.item)
        else:
            return Point(Fraction(x3), Fraction(y3))

    def neg_point(self, p1:Point):
        return Point(p1.x, self.p-p1.y)

    def sub_point(self, p1:Point, p2:Point):
        return self.add_point(p1, self.neg_point(p2))

    def scope(self, p1: Point, p2: Point):
        if p1.x == p2.x:
            raise ValueError("p1 == p2 or p1 + p2 = 0")

        return Fraction((p2.y - p1.y), (p2.x -p1.x))


    def y_recover(self, x, flag=False):
        x = x % self.p
        y2 = (x**3  + self.a * x + self.b) % self.p
        y = cipolla(y2, self.p)
        if y:
            if flag:
                return Point(x, max(y, self.p-y))
            else:
                return Point(x, min(y, self.p-y))
        return None

    def __contains__(self, p: Point):
        if p.z == 0:
            return True
        if self.gf:
            return self.gf(p.x**3 + self.a * p.x + self.b -  p.y**2).item == 0
        else:
            return p.x**3 + self.a * p.x + self.b == p.y**2


if __name__ == "__main__":
    E = EllipticCurve(2, 3, 13)
    p = E(6,6)
    p2 = E.double_point(p)
    p3 = E.add_point(p, p2)
    p4 = E.mul_point(p, 4)
    p5 = E.add_point(p, p4)
    p6 = E.mul_point(p, 6)

    print(p6 == E.add_point(p2, p4))

    print(p6 == E.double_point(p3))
    print(p6 == E.add_point(p, p5))
