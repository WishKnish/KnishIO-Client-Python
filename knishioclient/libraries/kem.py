from typing import List, Tuple, Optional, Dict
from Crypto.Hash import SHAKE128, SHAKE256, SHA3_256, SHA3_512
from functools import lru_cache

PARAMS: Dict[str, Tuple[int, int, int, int, int]] = {
    "512": (2, 3, 2, 10, 4),
    "768": (3, 2, 2, 10, 4),
    "1024": (4, 2, 2, 11, 5)
}

ZETA_NTT: List[int] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    1062, 1919, 193, 797, 2786, 3260, 569, 1746,
    296, 2447, 1339, 1476, 3046, 56, 2240, 1333,
    1426, 2094, 535, 2882, 2393, 2879, 1974, 821,
    289, 331, 3253, 1756, 1197, 2304, 2277, 2055,
    650, 1977, 2513, 632, 2865, 33, 1320, 1915,
    2319, 1435, 807, 452, 1438, 2868, 1534, 2402,
    2647, 2617, 1481, 648, 2474, 3110, 1227, 910,
    17, 2761, 583, 2649, 1637, 723, 2288, 1100,
    1409, 2662, 3281, 233, 756, 2156, 3015, 3050,
    1703, 1651, 2789, 1789, 1847, 952, 1461, 2687,
    939, 2308, 2437, 2388, 733, 2337, 268, 641,
    1584, 2298, 2037, 3220, 375, 2549, 2090, 1645,
    1063, 319, 2773, 757, 2099, 561, 2466, 2594,
    2804, 1092, 403, 1026, 1143, 2150, 2775, 886,
    1722, 1212, 1874, 1029, 2110, 2935, 885, 2154]

ZETA_MUL: List[int] = [
    17, -17, 2761, -2761, 583, -583, 2649, -2649,
    1637, -1637, 723, -723, 2288, -2288, 1100, -1100,
    1409, -1409, 2662, -2662, 3281, -3281, 233, -233,
    756, -756, 2156, -2156, 3015, -3015, 3050, -3050,
    1703, -1703, 1651, -1651, 2789, -2789, 1789, -1789,
    1847, -1847, 952, -952, 1461, -1461, 2687, -2687,
    939, -939, 2308, -2308, 2437, -2437, 2388, -2388,
    733, -733, 2337, -2337, 268, -268, 641, -641,
    1584, -1584, 2298, -2298, 2037, -2037, 3220, -3220,
    375, -375, 2549, -2549, 2090, -2090, 1645, -1645,
    1063, -1063, 319, -319, 2773, -2773, 757, -757,
    2099, -2099, 561, -561, 2466, -2466, 2594, -2594,
    2804, -2804, 1092, -1092, 403, -403, 1026, -1026,
    1143, -1143, 2150, -2150, 2775, -2775, 886, -886,
    1722, -1722, 1212, -1212, 1874, -1874, 1029, -1029,
    2110, -2110, 2935, -2935, 885, -885, 2154, -2154]


class KPKE(object):
    def __init__(self, param: str = '768') -> None:
        if param not in PARAMS:
            raise ValueError
        self.q: int = 3329
        self.n: int = 256
        self.k, self.eta1, self.eta2, self.du, self.dv = PARAMS[param]

    @lru_cache()
    def hash256(self, x: bytes) -> bytes:
        return SHA3_256.new(x).digest()

    @lru_cache()
    def split_coder(self, x: bytes) -> Tuple[bytes, bytes]:
        digest = SHA3_512.new(x).digest()
        return digest[0:32], digest[32:64]

    @lru_cache()
    def hash(self, s: bytes) -> bytes:
        return SHAKE256.new(s).read(32)

    @lru_cache()
    def prf(self, eta: int, s: bytes, b: int) -> bytes:
        return SHAKE256.new(s + bytes([b])).read(64 * eta)

    def compress(self, d: int, xv: List[int]) -> List[int]:
        return [(((x << d) + (self.q - 1) // 2) // self.q) % (1 << d)
                for x in xv]

    def decompress(self, d: int, yv: List[int]) -> List[int]:
        return [(self.q * y + (1 << (d - 1))) >> d for y in yv]

    def bits_to_bytes(self, b: bytearray) -> bytearray:
        l = len(b)
        a = bytearray(l // 8)
        for i in range(0, l, 8):
            x = 0
            for j in range(8):
                x += b[i + j] << j
            a[i // 8] = x
        return a

    def bytes_to_bits(self, b: bytes) -> bytearray:
        l = len(b)
        a = bytearray(8 * l)
        for i in range(0, 8 * l, 8):
            x = b[i // 8]
            for j in range(8):
                a[i + j] = (x >> j) & 1
        return a

    def byte_encode(self, d: int, f: List[int] | List[List[int]]) -> bytes:
        if isinstance(f[0], list):
            b = b''
            for x in f:
                b += self.byte_encode(d, x)
            return b
        if d < 12:
            m = 1 << d
        else:
            m = self.q
        b = bytearray(self.n * d)
        for i in range(self.n):
            a = f[i] % m
            for j in range(d):
                b[i * d + j] = a % 2
                a //= 2
        b = self.bits_to_bytes(b)
        return bytes(b)

    def byte_decode(self, d: int, b: bytes) -> List[int]:
        if d < 12:
            m = 1 << d
        else:
            m = self.q
        b = self.bytes_to_bits(b)
        f = []
        for i in range(self.n):
            x = 0
            for j in range(d):
                x += b[i * d + j] << j
            f += [x % m]
        return f

    def sample_ntt(self, b: bytes) -> List[int]:
        xof = SHAKE128.new(b)
        j = 0
        a: List[int] = []
        while j < self.n:
            c = xof.read(3)
            d1 = c[0] + self.n * (c[1] % 16)
            d2 = (c[1] // 16) + 16 * c[2]
            if d1 < self.q:
                a += [d1]
                j += 1
            if d2 < self.q and j < self.n:
                a += [d2]
                j += 1
        return a

    def sample_cbd(self, eta: int, b: bytes) -> List[int]:
        b = self.bytes_to_bits(b)
        f = [0] * self.n
        for i in range(self.n):
            x = sum(b[2 * i * eta:(2 * i + 1) * eta])
            y = sum(b[(2 * i + 1) * eta:(2 * i + 2) * eta])
            f[i] = (x - y) % self.q
        return f

    def ntt(self, f: List[int]) -> List[int]:
        f = f.copy()
        i = 1
        le = 128
        while le >= 2:
            for st in range(0, self.n, 2 * le):
                ze = ZETA_NTT[i]
                i += 1
                for j in range(st, st + le):
                    t = (ze * f[j + le]) % self.q
                    f[j + le] = (f[j] - t) % self.q
                    f[j] = (f[j] + t) % self.q
            le //= 2
        return f

    def ntt_inverse(self, f: List[int]) -> List[int]:
        f = f.copy()
        i = 127
        le = 2
        while le <= 128:
            for st in range(0, self.n, 2 * le):
                ze = ZETA_NTT[i]
                i -= 1
                for j in range(st, st + le):
                    t = f[j]
                    f[j] = (t + f[j + le]) % self.q
                    f[j + le] = (ze * (f[j + le] - t)) % self.q
            le *= 2
        f = [(x * 3303) % self.q for x in f]
        return f

    def multiply_ntts(self, f: List[int], g: List[int]) -> List[int]:
        h: List[int] = []
        for i in range(0, self.n, 2):
            h += self.base_case_multiply(f[i], f[i + 1], g[i], g[i + 1], ZETA_MUL[i // 2])
        return h

    def base_case_multiply(self, a0: int, a1: int, b0: int, b1: int, gam: int) -> List[int]:
        c0 = (a0 * b0 + a1 * b1 * gam) % self.q
        c1 = (a0 * b1 + a1 * b0) % self.q
        return [c0, c1]

    def poly_add(self, f: List[int], g: List[int]) -> List[int]:
        return [(f[i] + g[i]) % self.q for i in range(self.n)]

    def poly_sub(self, f: List[int], g: List[int]) -> List[int]:
        return [(f[i] - g[i]) % self.q for i in range(self.n)]

    def keygen(self, d: bytes) -> Tuple[bytes, bytes]:
        rho, sig = self.split_coder(d + bytes([self.k]))
        n = 0
        a: List[List[Optional[List[int]]]] = [[None] * self.k for _ in range(self.k)]
        for i in range(self.k):
            for j in range(self.k):
                a[i][j] = self.sample_ntt(rho + bytes([j, i]))

        s: List[Optional[List[int]]] = [None] * self.k
        for i in range(self.k):
            s[i] = self.sample_cbd(self.eta1, self.prf(self.eta1, sig, n))
            n += 1

        e: List[Optional[List[int]]] = [None] * self.k
        for i in range(self.k):
            e[i] = self.sample_cbd(self.eta1, self.prf(self.eta1, sig, n))
            n += 1

        s = [self.ntt(v) for v in s if v is not None]
        e = [self.ntt(v) for v in e if v is not None]
        t = e

        for i in range(self.k):
            for j in range(self.k):
                if a[i][j] is not None:
                    t[i] = self.poly_add(t[i], self.multiply_ntts(a[i][j], s[j]))

        ek_pke = self.byte_encode(12, t) + rho
        dk_pke = self.byte_encode(12, s)
        return ek_pke, dk_pke

    def encrypt(self, ek_pke: bytes, m: bytes, r: bytes) -> bytes:
        n = 0
        t = [self.byte_decode(12, ek_pke[384 * i:384 * (i + 1)]) for i in range(self.k)]
        rho = ek_pke[384 * self.k: 384 * self.k + 32]
        a: List[List[Optional[List[int]]]] = [[None] * self.k for _ in range(self.k)]

        for i in range(self.k):
            for j in range(self.k):
                a[i][j] = self.sample_ntt(rho + bytes([j, i]))

        y: List[Optional[List[int]]] = [None] * self.k
        for i in range(self.k):
            y[i] = self.sample_cbd(self.eta1, self.prf(self.eta1, r, n))
            n += 1

        e1: List[Optional[List[int]]] = [None] * self.k
        for i in range(self.k):
            e1[i] = self.sample_cbd(self.eta2, self.prf(self.eta2, r, n))
            n += 1

        e2 = self.sample_cbd(self.eta2, self.prf(self.eta2, r, n))

        y = [self.ntt(v) for v in y if v is not None]
        u = [[0] * self.n for _ in range(self.k)]

        for i in range(self.k):
            for j in range(self.k):
                if a[j][i] is not None:
                    u[i] = self.poly_add(u[i], self.multiply_ntts(a[j][i], y[j]))

        for i in range(self.k):
            u[i] = self.ntt_inverse(u[i])
            if e1[i] is not None:
                u[i] = self.poly_add(u[i], e1[i])

        mu = self.decompress(1, self.byte_decode(1, m))
        v = [0] * self.n

        for i in range(self.k):
            v = self.poly_add(v, self.multiply_ntts(t[i], y[i]))

        v = self.ntt_inverse(v)
        v = self.poly_add(v, e2)
        v = self.poly_add(v, mu)
        c1 = b''

        for i in range(self.k):
            c1 += self.byte_encode(self.du, self.compress(self.du, u[i]))
        c2 = self.byte_encode(self.dv, self.compress(self.dv, v))
        return c1 + c2

    def decrypt(self, dk_pke: bytes, c: bytes) -> bytes:
        c1 = c[0: 32 * self.du * self.k]
        c2 = c[32 * self.du * self.k: 32 * (self.du * self.k + self.dv)]
        up = [self.decompress(self.du, self.byte_decode(self.du, c1[32 * self.du * i: 32 * self.du * (i + 1)]))
              for i in range(self.k)]

        vp = self.decompress(self.dv, self.byte_decode(self.dv, c2))
        s = [self.byte_decode(12, dk_pke[384 * i:384 * (i + 1)]) for i in range(self.k)]
        w = [0] * self.n

        for i in range(self.k):
            w = self.poly_add(w, self.multiply_ntts(s[i], self.ntt(up[i])))
        w = self.poly_sub(vp, self.ntt_inverse(w))
        return self.byte_encode(1, self.compress(1, w))


class MLKEM(KPKE):
    def __init__(self, param: str = '768') -> None:
        super(MLKEM, self).__init__(param)

    def keygen(self, d: bytes, z: bytes) -> Tuple[bytes, bytes]:
        ek_pke, dk_pke = super(MLKEM, self).keygen(d)
        ek = ek_pke
        dk = dk_pke + ek + self.hash256(ek) + z
        return ek, dk

    def encapsulate(self, ek: bytes, m: bytes) -> Tuple[bytes, bytes]:
        k, r = self.split_coder(m + self.hash256(ek))
        c = super(MLKEM, self).encrypt(ek, m, r)
        return k, c

    def decapsulate(self, dk: bytes, c: bytes) -> bytes:
        dk_pke = dk[0: 384 * self.k]
        ek_pke = dk[384 * self.k: 768 * self.k + 32]
        h = dk[768 * self.k + 32: 768 * self.k + 64]
        z = dk[768 * self.k + 64: 768 * self.k + 96]
        mp = super(MLKEM, self).decrypt(dk_pke, c)
        kp, rp = self.split_coder(mp + h)
        kk = self.hash(z + c)
        cp = super(MLKEM, self).encrypt(ek_pke, mp, rp)
        if c != cp:
            kp = kk
        return kp

ml_kem768 = MLKEM()
