from fractions import Fraction

class GF:
    def __init__(self, p):
        self.p = p

    def __repr__(self) -> str:
        return f"GF({self.p})"

    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def inverse(self, a):
        if isinstance(a, GFItem):
            a = a.item
        gcd, x, y = self.extended_gcd(a, self.p)
        if gcd != 1:
            raise ValueError(f"{a} 在 GF({self.p}) 中没有逆元")
        else:
            return GFItem(x % self.p, self)

    def __eq__(self, other) -> bool:
        return self.p == other.p

    def __call__(self, item):
        return GFItem(item, self)

class GFItem:
    def __init__(self, item, parent: GF):
        self.item = item % parent.p
        self.parent = parent

    def __repr__(self) -> str:
        return f"GF({self.parent.p})({self.item})"

    def __add__(self, other):
        if self.parent != other.parent:
            raise ValueError("not in same GF")
        item = (self.item + other.item) % self.parent.p
        return GFItem(item, self.parent)

    def __mul__(self, other):
        if self.parent != other.parent:
            raise ValueError("not in same GF")
        item = (self.item * other.item) % self.parent.p
        return GFItem(item, self.parent)

    def __sub__(self, other):
        if self.parent != other.parent:
            raise ValueError("not in same GF")
        item = (self.item - other.item) % self.parent.p
        return GFItem(item, self.parent)

    def __truediv__(self, other):
        if other.item == 0:
             raise ZeroDivisionError(f"inverse mod (0, {self.parent.p}) not exist")
        return self * (~other)

    def __invert__(self):
        if self.item == 0:
            raise ZeroDivisionError(f"inverse mod (0, {self.parent.p}) not exist")
        return self.parent.inverse(self.item)

    def __pow__(self, v):
        if isinstance(v, GFItem):
            v = v.item
        item = pow(self.item, v, self.parent.p)
        return GFItem(item, self.parent)

if __name__ == "__main__":
    F = GF(17)
    a = F(7)
    b = F(8)
    print(f"{a} + {b} = {a+b}")
    print(f"{a} * {b} = {a*b}")
