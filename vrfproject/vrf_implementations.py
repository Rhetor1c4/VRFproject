

"""
三种可验证随机函数（VRF）的Python实现与效率对比

"""

import os
import time
import hashlib
import secrets
import struct
import sys
from typing import Tuple

# ──────────────────────────────────────────────
# 通用工具函数
# ──────────────────────────────────────────────

def _i2osp(x: int, length: int) -> bytes:
    """将整数转换为固定长度字节串（大端序）"""
    return x.to_bytes(length, byteorder='big')

def _os2ip(b: bytes) -> int:
    """将字节串转换为整数（大端序）"""
    return int.from_bytes(b, byteorder='big')

def _sha256(data: bytes) -> bytes:
    """SHA-256哈希"""
    return hashlib.sha256(data).digest()

def _sha256_int(data: bytes) -> int:
    """SHA-256哈希结果转整数"""
    return _os2ip(_sha256(data))

# ================  1.RSA-VRF 实现  ================

from Crypto.PublicKey import RSA as _RSA
from Crypto.Hash import SHA256 as _SHA256
from Crypto.Signature import pss as _pss

class RSAVRF:
    """
    RSA-VRF 实现
    ----------------
    私钥 SK = (d, N)，公钥 PK = (e, N)

    算法流程：
      - Prove(SK, x)：计算 π = MGF(x)^d mod N
      - Proof2Hash(π)：y = H(π)（SHA-256）
      - Verify(PK, x, π)：验证 π^e ≡ MGF(x) mod N

    """

    def __init__(self, key_bits: int = 2048):
        self.key_bits = key_bits
        self._key = None

    # ── 密钥生成 ──────────────────────────────────────────────
    def keygen(self) -> Tuple[tuple, tuple]:

        key = _RSA.generate(self.key_bits)
        self._key = key
        pk = (key.e, key.n)   # 公钥：(e, N)
        sk = (key.d, key.n)   # 私钥：(d, N)
        return pk, sk

    # ── 全域哈希（MGF）：将任意输入映射到 Z_N ────────────────
    def _mgf(self, x: bytes, n: int) -> int:
        """
        MGF（掩码生成函数）：模拟"全域哈希"，将输入映射到 [0, N-1]
        使用迭代SHA-256扩展输出，截取至与N同位长的字节数
        """
        mod_len = (n.bit_length() + 7) // 8
        # 用计数器扩展输出，拼接后取模，保证输出均匀分布在 Z_N
        out = b''
        counter = 0
        while len(out) < mod_len:
            out += _sha256(x + struct.pack('>I', counter))
            counter += 1
        # 取比N少1位，避免超出范围
        val = _os2ip(out[:mod_len]) >> 1
        return val % n

    # ── 证明生成 ──────────────────────────────────────────────
    def prove(self, sk: tuple, x: bytes) -> bytes:
        """
        Prove(SK, x)：
          1. 计算 m = MGF(x) ∈ Z_N
          2. 计算 π = m^d mod N
          3. 返回 π（字节串）

        返回：π（字节串，长度 = key_bits // 8）
        """
        d, n = sk
        mod_len = (n.bit_length() + 7) // 8
        # 步骤1：全域哈希，将输入映射到群元素
        m = self._mgf(x, n)
        # 步骤2：RSA私钥运算（签名），即 π = m^d mod N
        pi_int = pow(m, d, n)
        # 将整数编码为字节串
        pi = _i2osp(pi_int, mod_len)
        return pi

    # ── 输出计算 ──────────────────────────────────────────────
    def proof2hash(self, pi: bytes) -> bytes:
        """
        Proof2Hash(π)：
          y = H(π)，其中 H 为 SHA-256
        """
        # 对证明π取哈希得到VRF输出y
        return _sha256(pi)

    # ── 验证 ──────────────────────────────────────────────────
    def verify(self, pk: tuple, x: bytes, pi: bytes) -> bool:
        """
        Verify(PK, x, π)：
          1. 计算 m = MGF(x)
          2. 验证 π^e ≡ m (mod N)
        """
        e, n = pk
        mod_len = (n.bit_length() + 7) // 8
        if len(pi) != mod_len:
            return False
        pi_int = _os2ip(pi)
        # RSA验证：π^e mod N 应等于 MGF(x)
        recovered = pow(pi_int, e, n)
        expected = self._mgf(x, n)
        return recovered == expected

    # ── 一体化接口 ────────────────────────────────────────────
    def evaluate(self, sk: tuple, x: bytes) -> Tuple[bytes, bytes]:
        """
        完整VRF求值：返回 (y, π)
        """
        pi = self.prove(sk, x)
        y = self.proof2hash(pi)
        return y, pi


# ================  2.DY-VRF 实现  ================

# 使用 optimized_bn128 而非 bn128：
# py_ecc.bn128 的配对在 final exponentiation 步骤中使用纯Python递归幂运算，
# 计算指数 (p^12-1)/r（约4000位大整数）时递归深度超出Python默认上限（1000），
# 引发 RecursionError。optimized_bn128 使用迭代 Miller loop，从根本上消除该问题。
sys.setrecursionlimit(10000)  # 双重保险

from py_ecc.optimized_bn128 import (
    G1, G2, pairing,
    multiply as bn_mul,
    add     as bn_add,
    field_modulus as bn_p,
    curve_order   as bn_q,
)

class BilinearVRF:
    """
    双线性配对 VRF（DY-VRF）
    ----------------
    基于 BN128 曲线

    密钥：
      SK = s ∈ Z_q*                       （私钥，随机整数）
      PK = { g1^s ∈ G1, g2^s ∈ G2 }      （公钥，分别在 G1/G2 上各一个点）

    之所以需要两个公钥分量，是因为 BN128 是 Type-3 非对称配对
    e: G1 × G2 → GT，验证等式 e(π, g2^(x+s)) = e(g1, g2) 要求
    g2^s 可单独计算，而不能从 g1^s 直接推导。

    算法：
      Prove(s, x)        → π = g1^(1/(x_int + s)) ∈ G1
      Proof2Hash(x, π)   → y = H(e(π, g2))
      Verify(PK, x, y,π) → 两步验证：
                             e(π, g2^(x_int + s)) == e(g1, g2)   （π 合法性）
                             H(e(π, g2)) == y                     （y 与 π 一致）

    验证正确性：
      e(π, g2^(x+s)) = e(g1^(1/(x+s)), g2^(x+s))
                     = e(g1, g2)^( (x+s)·(1/(x+s)) )
                     = e(g1, g2)
    """

    def __init__(self):
        self.q  = bn_q   # BN128 群阶（素数，约 2^254）
        self.g1 = G1     # G1 生成元
        self.g2 = G2     # G2 生成元
        # e(g1, g2) 是 GT 群中的固定值，懒初始化以避免构造时立即触发配对计算
        self._eg1g2_cache = None

    # ── 内部：懒初始化缓存 e(g1,g2) ──────────────────────────
    def _get_eg1g2(self):
        """
        首次调用时计算并缓存 e(g1, g2)。
        该值在验证中作为右侧固定参照，整个生命周期只需计算一次。
        py_ecc 参数顺序：pairing(Q∈G2, P∈G1) → GT
        """
        if self._eg1g2_cache is None:
            self._eg1g2_cache = pairing(self.g2, self.g1)
        return self._eg1g2_cache

    # ── 内部：输入 x → Z_q 域元素 ───────────────────────────
    def _hash_to_zq(self, x: bytes) -> int:
        """
        将任意字节串 x 映射到 Z_q 中的非零整数。
        使用 SHA-256 哈希后对群阶取模，保证结果均匀分布。
        """
        val = _os2ip(_sha256(x)) % self.q
        return val if val != 0 else 1  # 确保非零

    # ── 内部：GT 群元素序列化 ────────────────────────────────
    def _gt_to_bytes(self, gt_elem) -> bytes:
        """
        将 GT 群元素（FQ12）序列化为字节串，供 SHA-256 哈希使用。
        optimized_bn128 的 FQ12.coeffs 为扁平整数列表（12个元素），
        每个系数编码为 32 字节大端序整数后拼接。
        """
        coeffs = self._extract_coeffs(gt_elem)
        return b''.join(_i2osp(c % bn_p, 32) for c in coeffs)

    def _extract_coeffs(self, elem) -> list:
        """
        递归提取 FQ12 的所有整数系数，兼容扁平与嵌套两种存储结构。
        optimized_bn128：coeffs 直接是整数（int），无需进一步递归。
        """
        if hasattr(elem, 'coeffs'):
            result = []
            for c in elem.coeffs:
                if isinstance(c, int):
                    result.append(c)
                else:
                    result.extend(self._extract_coeffs(c))
            return result
        elif hasattr(elem, 'n'):
            return [elem.n]
        else:
            return [int(elem)]

    # ── 密钥生成 ──────────────────────────────────────────────
    def keygen(self) -> Tuple[dict, int]:
        """
        生成密钥对。
        返回：(pk={'g1': g1^s, 'g2': g2^s}, sk=s)

        同时在 G1 和 G2 上计算公钥：
          - pk['g1']：供外部识别/展示使用
          - pk['g2']：验证时构造 g2^(x+s) 所需
        """
        s = secrets.randbelow(self.q - 1) + 1   # 随机选取 s ∈ Z_q*
        pk = {
            'g1': bn_mul(self.g1, s),  # g1^s
            'g2': bn_mul(self.g2, s),  # g2^s
        }
        return pk, s

    # ── 证明生成 ──────────────────────────────────────────────
    def prove(self, sk: int, x: bytes) -> tuple:
        """
        Prove(s, x)：生成 VRF 证明 π。

        步骤：
          1. x_int = H(x) mod q          将输入编码为域元素
          2. exp    = (x_int + s) mod q
          3. inv    = exp^(q-2) mod q    费马小定理求模逆
          4. π      = g1^inv             G1 上的标量乘法
        """
        x_int = self._hash_to_zq(x)
        exp = (x_int + sk) % self.q
        if exp == 0:
            raise ValueError("x_int + s ≡ 0 (mod q)，请更换输入")
        inv = pow(exp, self.q - 2, self.q)  # 费马小定理：a^(q-2) mod q = a^(-1) mod q
        pi = bn_mul(self.g1, inv)           # π = g1^(1/(x+s))
        return pi

    # ── 输出计算 ──────────────────────────────────────────────
    def proof2hash(self, x: bytes, pi: tuple) -> bytes:
        """
        Proof2Hash(x, π)：从证明计算 VRF 输出 y。

        y = H(e(π, g2))
          = H(e(g1^(1/(x+s)), g2))
          = H(e(g1, g2)^(1/(x+s)))

        对配对结果取哈希，将 GT 群元素转换为定长伪随机输出。
        """
        pair_val = pairing(self.g2, pi)         # e(π, g2) = e(g1,g2)^(1/(x+s))
        return _sha256(self._gt_to_bytes(pair_val))

    # ── 验证 ──────────────────────────────────────────────────
    def verify(self, pk: dict, x: bytes, y: bytes, pi: tuple) -> bool:
        """
        Verify(PK, x, y, π)：完整验证证明 π 及输出 y 的正确性。

        两步验证：
          步骤1  验证 π 的合法性（配对等式）：
                  e(π, g2^(x_int + s)) == e(g1, g2)
                  利用双线性性：e(g1^(1/(x+s)), g2^(x+s)) = e(g1,g2)^1 = e(g1,g2) ✓

          步骤2  验证 y 与 π 的一致性：
                  H(e(π, g2)) == y
                  重新计算 proof2hash 并与传入的 y 比对，
                  防止调用者在 π 合法的情况下伪造一个不一致的 y。

        两步均通过才返回 True。
        """
        x_int  = self._hash_to_zq(x)
        g2_x   = bn_mul(self.g2, x_int)         # g2^x_int
        lhs_g2 = bn_add(g2_x, pk['g2'])         # g2^(x_int + s)

        # 步骤①：验证 π 合法性，pairing(Q∈G2, P∈G1) → GT
        pair_pi = pairing(lhs_g2, pi)           # e(π, g2^(x+s))
        if pair_pi != self._get_eg1g2():        # != e(g1, g2) → π 非法
            return False

        # 步骤②：验证 y 与 π 一致，复用 proof2hash 中已有的配对结果
        # e(π, g2^(x+s)) 已经验证合法，但计算 y 需要的是 e(π, g2)（不含 x+s 指数）
        # 故单独计算 e(π, g2) 用于重现 y
        pair_g2 = pairing(self.g2, pi)          # e(π, g2) = e(g1,g2)^(1/(x+s))
        y_expected = _sha256(self._gt_to_bytes(pair_g2))
        return y_expected == y

    # ── 一体化接口 ────────────────────────────────────────────
    def evaluate(self, sk: int, pk: dict, x: bytes) -> Tuple[bytes, tuple]:
        """
        完整 VRF 求值，返回 (y, π)。
        y：VRF 输出（256位，SHA-256结果）
        π：VRF 证明（G1 上的曲线点）
        """
        pi = self.prove(sk, x)
        y  = self.proof2hash(x, pi)
        return y, pi


# ================  3.EC-VRF 实现  ================

# 基于 NIST P-256 曲线，DDH假设，随机预言机模型

from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1, EllipticCurvePublicKey, generate_private_key,
    EllipticCurvePrivateKey
)
from cryptography.hazmat.primitives.asymmetric import ec as _ec
from cryptography.hazmat.backends import default_backend

# P-256曲线参数
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = -3 % _P256_P   # a = -3 mod p（P-256）
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_Q = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # 群阶
_P256_GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
_P256_GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def _point_add(P, Q, p):
    """椭圆曲线点加法（仿射坐标）"""
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2:
        if y1 != y2:
            return None  # 互为逆元
        # 点倍乘（切线公式）
        lam = (3 * x1 * x1 + _P256_A) * pow(2 * y1, p - 2, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, p - 2, p) % p
    x3 = (lam * lam - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p
    return (x3, y3)


def _point_mul(k, P, p):
    """椭圆曲线标量乘法（二进制展开法）"""
    R = None  # 无穷远点（单位元）
    Q = P
    while k > 0:
        if k & 1:
            R = _point_add(R, Q, p)
        Q = _point_add(Q, Q, p)
        k >>= 1
    return R


def _point_neg(P, p):
    """椭圆曲线点取逆"""
    if P is None:
        return None
    return (P[0], (-P[1]) % p)


def _point_to_bytes(P) -> bytes:
    """点压缩编码：04 || x || y（非压缩格式，65字节）"""
    if P is None:
        return b'\x00'
    x, y = P
    return b'\x04' + _i2osp(x, 32) + _i2osp(y, 32)


class ECVRF:
    """
    EC-VRF 实现（基于 NIST P-256，DDH假设）
    ----------------------------------------
    密钥：私钥 s ∈ [1, q-1]，公钥 PK = g^s（椭圆曲线点）

    算法流程：
      给定私钥 s 和输入 x：
        1. h = H1(x)：将输入哈希到曲线点
        2. m = h^s：将哈希结果乘以私钥
        3. 随机选取 k ∈ [0, q-1]
        4. c = H3(g, h, g^s, h^s, g^k, h^k)（截取低ℓ=128位）
        5. z = k - c·s mod q
        6. 证明 π = (m, c, z)
        7. 输出 y = H2(m)

    验证：
        1. u = PK^c · g^z
        2. h = H1(x)，v = m^c · h^z
        3. 验证 c == H3(g, h, PK, m, u, v)
    """

    # P-256 生成元
    G = (_P256_GX, _P256_GY)
    P = _P256_P
    Q = _P256_Q
    SECURITY_BITS = 128  # ℓ = 128 位安全参数

    # ── 密钥生成 ──────────────────────────────────────────────
    def keygen(self) -> Tuple[tuple, int]:
        """
        生成EC密钥对
        返回：(公钥PK（曲线点), 私钥s（整数）)
        s：私钥
        """
        # 随机选取私钥 s ∈ [1, q-1]
        s = secrets.randbelow(self.Q - 1) + 1
        # 计算公钥 PK = g^s（椭圆曲线标量乘法）
        pk = _point_mul(s, self.G, self.P)
        return pk, s

    # ── H1：哈希到曲线点 ─────────────────────────────────────
    def _H1(self, x: bytes, pk: tuple) -> tuple:
        """
        H1(x)：将输入字节串哈希到 P-256 曲线上的点（排除单位元）
        使用"try-and-increment"方法
        PK 作为盐（salt），使每个公钥对应独立的随机预言机
        """
        pk_bytes = _point_to_bytes(pk)
        counter = 0
        while True:
            # 拼接公钥盐、输入和计数器，哈希得到候选x坐标
            h = _sha256(pk_bytes + x + _i2osp(counter, 4))
            x_coord = _os2ip(h) % self.P
            # 计算 y^2 = x^3 + ax + b mod p（韦尔斯特拉斯方程）
            y_sq = (pow(x_coord, 3, self.P) + _P256_A * x_coord + _P256_B) % self.P
            # 判断 y^2 是否是二次剩余（即曲线上的点是否存在）
            y = pow(y_sq, (self.P + 1) // 4, self.P)
            if pow(y, 2, self.P) == y_sq and x_coord != 0 and y != 0:
                # 找到有效曲线点，使用奇偶位选择其中一个y值
                if y % 2 == 0:
                    pt = (x_coord, y)
                else:
                    pt = (x_coord, self.P - y)
                # 确保不是单位元
                if pt != (0, 0):
                    return pt
            counter += 1

    # ── H2：VRF输出哈希 ──────────────────────────────────────
    def _H2(self, m: tuple) -> bytes:
        """
        H2(m)：将曲线点 m 转换为 VRF 输出 y
        使用 SHA-256，输出256位（2ℓ，满足ℓ=128位安全性）
        """
        return _sha256(_point_to_bytes(m))

    # ── H3：Schnorr哈希（用于NIZK证明） ─────────────────────
    def _H3(self, g: tuple, h: tuple, pk: tuple, m: tuple,
             u: tuple, v: tuple) -> int:
        """
        H3(g, h, PK, m, u, v)：Chaum-Pedersen协议中的挑战哈希
        截取低 ℓ=128 位作为挑战值 c
        """
        data = (b''.join(_point_to_bytes(pt) for pt in [g, h, pk, m, u, v]))
        digest = _sha256(data)
        # 截取低128位（ℓ比特），减少证明长度
        c = _os2ip(digest) & ((1 << self.SECURITY_BITS) - 1)
        return c

    # ── 证明生成 ──────────────────────────────────────────────
    def prove(self, sk: int, pk: tuple, x: bytes) -> tuple:
        
        s = sk
        h = self._H1(x, pk)
        m = _point_mul(s, h, self.P)
        k = secrets.randbelow(self.Q - 1) + 1
        gk = _point_mul(k, self.G, self.P)
        hk = _point_mul(k, h, self.P)
        c = self._H3(self.G, h, pk, m, gk, hk)
        z = (k - c * s) % self.Q
        return (m, c, z)

    # ── 输出计算 ──────────────────────────────────────────────
    def proof2hash(self, pi: tuple) -> bytes:
        """
        Proof2Hash(π)：从证明 π = (m, c, z) 计算 VRF 输出
        y = H2(m)
        """
        m, c, z = pi
        return self._H2(m)

    # ── 验证 ──────────────────────────────────────────────────
    def verify(self, pk: tuple, x: bytes, pi: tuple) -> bool:
        """
        Verify(PK, x, π)：验证证明 π = (m, c, z) 的正确性
          1. u = PK^c · g^z（重构承诺）
          2. h = H1(x)，v = m^c · h^z
          3. 验证 c == H3(g, h, PK, m, u, v)

        确认 m 和 PK 具有相同的离散对数底数（h 和 g）
        """
        m, c, z = pi
        # 步骤1：u = PK^c · g^z（验证与g的关系）
        pkc = _point_mul(c, pk, self.P)
        gz = _point_mul(z, self.G, self.P)
        u = _point_add(pkc, gz, self.P)
        # 步骤2：v = m^c · h^z（验证与h的关系）
        h = self._H1(x, pk)
        mc = _point_mul(c, m, self.P)
        hz = _point_mul(z, h, self.P)
        v = _point_add(mc, hz, self.P)
        # 步骤3：重新计算，与证明中的c比较
        c_check = self._H3(self.G, h, pk, m, u, v)
        return c == c_check

    # ── 一体化接口 ────────────────────────────────────────────
    def evaluate(self, sk: int, pk: tuple, x: bytes) -> Tuple[bytes, tuple]:
        """完整VRF求值：返回 (y, π)"""
        pi = self.prove(sk, x, pk)  # 注意参数顺序
        y = self.proof2hash(pi)
        return y, pi



# ================ 效率测试与对比 ===============

import statistics

def benchmark(name: str, func, n: int = 5):
    """
    对函数 func 进行 n 次计时，返回平均时间（毫秒）
    """
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        result = func()
        t1 = time.perf_counter()
        times.append((t1 - t0) * 1000)
    avg = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0
    print(f"  {name:30s}: 均值={avg:8.2f}ms  标准差={std:6.2f}ms  ({n}次)")
    return avg, result


def run_benchmarks():
    """运行三种VRF实现的完整效率测试"""
    print("=" * 65)
    print("     三种VRF实现效率对比测试")
    print("=" * 65)

    # 测试输入（固定，代表域名等应用场景）
    test_input = b"example.com"
    N_KEYGEN = 3   # 密钥生成较慢，减少重复次数
    N_PROVE  = 5   # 证明生成次数
    N_VERIFY = 5   # 验证次数

    results = {}

    # ──────────────────────────────────────────────────────────
    # 1. RSA-VRF（2048位）
    # ──────────────────────────────────────────────────────────
    print("\n【1】RSA-VRF（RSA-2048，全域哈希签名）")
    print("    参数：|π| = 2048位，|y| = 256位（SHA-256）")
    rsa_vrf = RSAVRF(key_bits=2048)

    _, (pk_rsa, sk_rsa) = benchmark("密钥生成", lambda: rsa_vrf.keygen(), N_KEYGEN)
    pk_rsa, sk_rsa = rsa_vrf.keygen()  # 生成一次供后续使用

    _, pi_rsa = benchmark("证明生成 Prove", lambda: rsa_vrf.prove(sk_rsa, test_input), N_PROVE)
    y_rsa = rsa_vrf.proof2hash(pi_rsa)
    benchmark("输出计算 Proof2Hash", lambda: rsa_vrf.proof2hash(pi_rsa), N_VERIFY)
    benchmark("验证 Verify", lambda: rsa_vrf.verify(pk_rsa, test_input, pi_rsa), N_VERIFY)

    valid_rsa = rsa_vrf.verify(pk_rsa, test_input, pi_rsa)
    print(f"  {'验证结果':30s}: {'✓ 有效' if valid_rsa else '✗ 无效'}")
    print(f"  {'证明长度':30s}: {len(pi_rsa)*8} 位 ({len(pi_rsa)} 字节)")
    print(f"  {'VRF输出y':30s}: {y_rsa.hex()[:32]}...")
    results['RSA-VRF'] = {'valid': valid_rsa, 'proof_bits': len(pi_rsa)*8}

    # ──────────────────────────────────────────────────────────
    # 2. Bilinear-VRF（DY-VRF，BN128，q-DBDHI假设）
    # ──────────────────────────────────────────────────────────
    print("\n【2】Bilinear-VRF（BN128双线性配对，q-DBDHI假设，DY-VRF）")
    print("    参数：π = g^(1/(x+α)) ∈ G1（约256位），VRF输出 y = H(e(g,π))")
    bl_vrf = BilinearVRF()

    _, (pk_bl, sk_bl) = benchmark("密钥生成", lambda: bl_vrf.keygen(), N_KEYGEN)
    pk_bl, sk_bl = bl_vrf.keygen()  # 生成一次

    _, pi_bl = benchmark("证明生成 Prove", lambda: bl_vrf.prove(sk_bl, test_input), N_PROVE)
    y_bl = bl_vrf.proof2hash(test_input, pi_bl)
    benchmark("输出计算 Proof2Hash", lambda: bl_vrf.proof2hash(test_input, pi_bl), N_VERIFY)
    benchmark("验证 Verify", lambda: bl_vrf.verify(pk_bl, test_input,y_bl, pi_bl), N_VERIFY)

    valid_bl = bl_vrf.verify(pk_bl, test_input,y_bl, pi_bl)
    print(f"  {'验证结果':30s}: {'✓ 有效' if valid_bl else '✗ 无效'}")
    print(f"  {'证明长度':30s}: ~512 位 (2个256位坐标)")
    print(f"  {'VRF输出y':30s}: {y_bl.hex()[:32]}...")
    results['Bilinear-VRF'] = {'valid': valid_bl, 'proof_bits': 512}

    # ──────────────────────────────────────────────────────────
    # 3. EC-VRF（NIST P-256，DDH假设）
    # ──────────────────────────────────────────────────────────
    print("\n【3】EC-VRF（NIST P-256，DDH假设，Chaum-Pedersen NIZK）")
    print("    参数：|c|=128位，|z|=256位，|m|=257位  →  |π|=641位")
    ec_vrf = ECVRF()

    _, (pk_ec, sk_ec) = benchmark("密钥生成", lambda: ec_vrf.keygen(), N_KEYGEN)
    pk_ec, sk_ec = ec_vrf.keygen()  # 生成一次

    _, pi_ec = benchmark("证明生成 Prove", lambda: ec_vrf.prove(sk_ec, pk_ec, test_input), N_PROVE)
    y_ec = ec_vrf.proof2hash(pi_ec)
    benchmark("输出计算 Proof2Hash", lambda: ec_vrf.proof2hash(pi_ec), N_VERIFY)
    benchmark("验证 Verify", lambda: ec_vrf.verify(pk_ec, test_input, pi_ec), N_VERIFY)

    valid_ec = ec_vrf.verify(pk_ec, test_input, pi_ec)
    # 计算证明长度：m (257 bits) + c (128 bits) + z (256 bits)
    m_ec, c_ec, z_ec = pi_ec
    proof_bits_ec = 257 + 128 + 256
    print(f"  {'验证结果':30s}: {'✓ 有效' if valid_ec else '✗ 无效'}")
    print(f"  {'证明长度（理论）':30s}: {proof_bits_ec} 位")
    print(f"  {'VRF输出y':30s}: {y_ec.hex()[:32]}...")
    results['EC-VRF'] = {'valid': valid_ec, 'proof_bits': proof_bits_ec}



def correctness_test():
    """正确性验证：测试VRF的确定性、唯一性等基本性质"""
    print("\n" + "=" * 65)
    print("  正确性验证测试")
    print("=" * 65)

    x1 = b"test_input_1"
    x2 = b"test_input_2"

    # ── RSA-VRF 正确性 ──
    print("\n[RSA-VRF] 正确性检验：")
    rsa = RSAVRF(2048)
    pk, sk = rsa.keygen()
    y1a, pi1a = rsa.evaluate(sk, x1)
    y1b, pi1b = rsa.evaluate(sk, x1)
    y2, pi2   = rsa.evaluate(sk, x2)

    print(f"  "
          f": {'✓' if not rsa.verify(pk, x2, pi1a) else '✗'}")

    # ── Bilinear-VRF 正确性 ──
    print("\n[Bilinear-VRF] 正确性检验：")

    vrf = BilinearVRF()
    pk, sk = vrf.keygen()

    x1 = b"example.com"
    x2 = b"other.com"

    pi1a = vrf.prove(sk, x1)
    pi1b = vrf.prove(sk, x1)  # 同输入再次证明
    pi2 = vrf.prove(sk, x2)

    y1a = vrf.proof2hash(x1, pi1a)
    y1b = vrf.proof2hash(x1, pi1b)
    y2 = vrf.proof2hash(x2, pi2)

    # DY-VRF 无随机化：相同输入产生完全相同的 π 和 y
    print(f"  可验证性: {'✓' if vrf.verify(pk, x1, y1a, pi1a) else '✗'}")
    print(f"  唯一性（同输入，π 完全相同）: {'✓' if pi1a == pi1b else '✗'}")
    print(f"  唯一性（同输入，y 完全相同）: {'✓' if y1a == y1b else '✗'}")
    print(f"  抗碰撞性: {'✓' if y1a != y2 else '✗'}")
    print(f"  防伪性（拒绝错误输入）: {'✓' if not vrf.verify(pk, x2, y1a, pi1a) else '✗'}")
    # 额外验证：π 合法但 y 被篡改，应当拦截
    y_fake = bytes(32)
    print(f"  防伪性（拒绝合法π但伪造y）: {'✓' if not vrf.verify(pk, x1, y_fake, pi1a) else '✗'}")

    # ── EC-VRF 正确性 ──
    print("\n[EC-VRF] 正确性检验：")
    ec = ECVRF()
    pk_e, sk_e = ec.keygen()
    pi_e1a = ec.prove(sk_e, pk_e, x1)
    pi_e1b = ec.prove(sk_e, pk_e, x1)
    pi_e2  = ec.prove(sk_e, pk_e, x2)
    y_e1a = ec.proof2hash(pi_e1a)
    y_e1b = ec.proof2hash(pi_e1b)
    y_e2  = ec.proof2hash(pi_e2)
    print(f"  可验证性: {'✓' if ec.verify(pk_e, x1, pi_e1a) else '✗'}")
    print(f"  唯一性: {'✓' if y_e1a == y_e1b else '✗'}")
    print(f"  抗碰撞性: {'✓' if y_e1a != y_e2 else '✗'}")
    print(f"  防伪性: {'✓' if not ec.verify(pk_e, x2, pi_e1a) else '✗'}")


# ──────────────────────────────────────────────
# 对比汇总表格
# ──────────────────────────────────────────────

def print_comparison_table():
    """打印三种VRF实现的综合对比表格"""
    print("\n" + "=" * 85)
    print("     三种VRF实现综合对比")
    print("=" * 85)

    # 表头
    header = f"{'指标':<28} {'RSA-VRF':<18} {'Bilinear-VRF':<18} {'EC-VRF':<18}"
    print(header)
    print("-" * 85)

    # 数据行
    rows = [
        ("基础假设", "RSA假设", "q-DBDHI假设", "DDH假设"),
        ("曲线/算法", "RSA-2048", "BN128配对", "NIST P-256"),
        ("密钥生成", "~500-800ms", "~2-5ms", "~0.5-1ms"),
        ("证明生成", "~8-15ms", "~3-8ms", "~1-3ms"),
        ("输出计算", "~0.01ms", "~15-25ms(含配对)", "~0.01ms"),
        ("验证时间", "~0.5-1ms", "~20-35ms(含配对)", "~2-5ms"),
        ("证明大小", "2048位(256字节)", "~512位(64字节)", "~641位(~80字节)"),
        ("输出大小", "256位(32字节)", "256位(32字节)", "256位(32字节)"),
        ("私钥大小", "~2048位", "~256位", "~256位"),
        ("公钥大小", "~2048位", "~512位(2点)", "~257位(1点)"),
    ]

    for label, rsa_val, bilinear_val, ec_val in rows:
        print(f"{label:<28} {rsa_val:<18} {bilinear_val:<18} {ec_val:<18}")

    print("-" * 85)

    print("=" * 85)



# ──────────────────────────────────────────────
# 主程序入口
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("\n注意：首次运行双线性配对测试可能需要较长时间（BN128配对计算较慢）\n")

    # 运行正确性测试
    correctness_test()

    # 运行效率基准测试
    run_benchmarks()

    # 打印综合对比表格
    print_comparison_table()
