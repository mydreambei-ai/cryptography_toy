from elliptic_curve import EllipticCurve

p = 2**255 - 19
order = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED
a = 42204101795669822316448953119945047945709099015225996174933988943478124189485
b = 13148341720542919587570920744190446479425344491440436116213316435534172959396
Ed25519 = EllipticCurve(a, b, p=p, order=order)

Ed25519_G = Ed25519(
    19210687000535497554771480197334579066178916638360430415404683479331899109173,
    18895136298852160426215908827706757709362468741134365248309716069351496097044,
)


def point_compress(point):
    x, y = point.x, point.y
    if y > (p >> 1):
        return ((x << 1) ^ 1).to_bytes(32, "little")
    return (x << 1).to_bytes(32, "little")


def point_decompress(m: bytes):
    x = int.from_bytes(m, "little")
    if x & 1:
        return Ed25519.y_recover((x ^ 1) >> 1, flag=True)
    return Ed25519.y_recover(x >> 1, flag=False)
