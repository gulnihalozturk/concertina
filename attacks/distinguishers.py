#!/usr/bin/env python3
"""Verifies the distinguishers of Section 2.2 ("Design Minimality").

For each simplified variant V1-V6 of Concertina, the corresponding
distinguisher is run many times, both against the variant and against the full
Concertina construction. The relation of Table 2 holds with probability one
for the variant and (essentially) never for Concertina.

    pip install cryptography
    python3 attacks/distinguishers.py [--trials N]

All variants use the reference primitives of python/scheme_ref.py (AES,
HMAC-SHA3-256 or HMAC-SHA-256, SP 800-108 key derivation, the counter mode of
Concertina, and the octet role codes 0x02/0x01).
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
import scheme_ref as ref  # noqa: E402
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # noqa: E402

xor = ref.xor


def aes_dec(key, block):
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(block) + d.finalize()


def delta(x):
    return xor(x[:16], x[16:])


class Mode:
    """Concertina or one of its simplified variants.

    no_in:   V1, no input hash (U = P_h)
    no_out:  V2, no output hash (C_h = V)
    seed:    "UV" (Concertina), "U" (V3) or "V" (V4)
    rounds:  4 (Concertina) or 3 (V5)
    head:    "feistel" (Concertina) or "twobranch" (V6)
    enc_seed: V6 only, additionally encrypt the counter seed
    """

    def __init__(self, hname="sha3", no_in=False, no_out=False, seed="UV", rounds=4,
                 head="feistel", enc_seed=False):
        self.h = hname
        self.K = ref.derive(hname, os.urandom(16))
        self.no_in, self.no_out, self.seed = no_in, no_out, seed
        self.rounds, self.head, self.enc_seed = rounds, head, enc_seed

    def E(self, u, x):
        return ref.aes_ecb(self.K[u], x)

    def mask(self, tail, role, T, disabled):
        if disabled:
            return bytes(32)
        return ref.H(self.h, self.K["hash"], tail + role + T)

    # --- head permutations ---
    def feistel(self, U):
        U1, U2 = U[:16], U[16:]
        R = xor(U2, self.E("1", U1))
        L = xor(U1, self.E("2", R))
        V2 = xor(R, self.E("3", L))
        V1 = L if self.rounds == 3 else xor(L, self.E("4", V2))
        return V1 + V2

    def feistel_inv(self, V):
        V1, V2 = V[:16], V[16:]
        L = V1 if self.rounds == 3 else xor(V1, self.E("4", V2))
        R = xor(V2, self.E("3", L))
        U1 = xor(L, self.E("2", R))
        U2 = xor(R, self.E("1", U1))
        return U1 + U2

    def seed_of(self, U, V):
        return {"UV": xor(delta(U), delta(V)), "U": delta(U), "V": delta(V)}[self.seed]

    def ctr(self, S, data):
        if self.enc_seed:
            S = self.E("ctr", S)
        return ref.ctr(self.K["ctr"], S, data)

    # --- encryption / decryption ---
    def enc(self, T, P):
        Ph, Pb = P[:32], P[32:]
        X = self.mask(Pb, b"\x02", T, self.no_in)
        if self.head == "twobranch":
            A1, A2 = X[:16], X[16:]
            F = self.E("1", xor(P[:16], A2))
            B = self.E("1", xor(xor(P[16:32], A1), F))
            Cb = self.ctr(xor(F, B), Pb)
            Y = self.mask(Cb, b"\x01", T, self.no_out)
            C2 = self.E("1", xor(B, Y[:16]))
            C1 = self.E("1", xor(xor(F, Y[16:]), C2))
            return C1 + C2 + Cb
        U = xor(Ph, X)
        V = self.feistel(U)
        Cb = self.ctr(self.seed_of(U, V), Pb)
        Y = self.mask(Cb, b"\x01", T, self.no_out)
        return xor(V, Y) + Cb

    def dec(self, T, C):
        Ch, Cb = C[:32], C[32:]
        Y = self.mask(Cb, b"\x01", T, self.no_out)
        if self.head == "twobranch":
            A3, A4 = Y[:16], Y[16:]
            B = xor(aes_dec(self.K["1"], C[16:32]), A3)
            F = xor(xor(aes_dec(self.K["1"], C[:16]), A4), C[16:32])
            Pb = self.ctr(xor(F, B), Cb)
            X = self.mask(Pb, b"\x02", T, self.no_in)
            P2 = xor(xor(aes_dec(self.K["1"], B), X[:16]), F)
            P1 = xor(aes_dec(self.K["1"], F), X[16:])
            return P1 + P2 + Pb
        V = xor(Ch, Y)
        U = self.feistel_inv(V)
        Pb = self.ctr(self.seed_of(U, V), Cb)
        X = self.mask(Pb, b"\x02", T, self.no_in)
        return xor(U, X) + Pb


R = os.urandom


# --- distinguishers of Table 2; each returns True if the relation holds ---
def d_v1(m, T):
    Ph, Pb, Pb2 = R(32), R(16), R(16)
    C, C2 = m.enc(T, Ph + Pb), m.enc(T, Ph + Pb2)
    return xor(C[32:], C2[32:]) == xor(Pb, Pb2)


def d_v2(m, T):
    C = m.enc(T, R(32) + R(16))
    Cb2 = R(16)
    P = m.dec(T, C)
    P2 = m.dec(T, C[:32] + Cb2)
    return xor(P[32:], P2[32:]) == xor(C[32:], Cb2)


def d_v3(m, T):
    P1, P2, Pb, D = R(16), R(16), R(16), R(16)
    return m.enc(T, P1 + P2 + Pb)[32:] == m.enc(T, xor(P1, D) + xor(P2, D) + Pb)[32:]


def d_v4(m, T):
    C1, C2, Cb, D = R(16), R(16), R(16), R(16)
    return m.dec(T, C1 + C2 + Cb)[32:] == m.dec(T, xor(C1, D) + xor(C2, D) + Cb)[32:]


def d_v5(m, T):
    P1, P2, P2p = R(16), R(16), R(16)
    C, Cp = m.enc(T, P1 + P2), m.enc(T, P1 + P2p)
    Q = m.dec(T, C[:16] + xor(xor(C[16:32], P2), P2p))
    return Q[:16] == xor(xor(P1, C[:16]), Cp[:16])


def d_v6(m, T):
    P1, P2, P2p = R(16), R(16), R(16)
    C, Cp = m.enc(T, P1 + P2), m.enc(T, P1 + P2p)
    Q = m.dec(T, C[:16] + Cp[16:32])
    return Q[16:32] == xor(xor(P2p, C[16:32]), Cp[16:32])


CASES = [
    ("V1", "no input hash", dict(no_in=True), d_v1, 2),
    ("V2", "no output hash", dict(no_out=True), d_v2, 2),
    ("V3", "seed from U only", dict(seed="U"), d_v3, 2),
    ("V4", "seed from V only", dict(seed="V"), d_v4, 2),
    ("V5", "three round head (2n-bit messages)", dict(rounds=3), d_v5, 3),
    ("V6", "two branch head (2n-bit messages)", dict(head="twobranch"), d_v6, 3),
    ("V6'", "two branch head, encrypted seed", dict(head="twobranch", enc_seed=True), d_v6, 3),
]


def check_round_trips(hname):
    for kw in [{}] + [c[2] for c in CASES]:
        m = Mode(hname, **kw)
        for n in (32, 33, 48, 100):
            T, P = R(16), R(n)
            assert m.dec(T, m.enc(T, P)) == P, (kw, n)
    # the full construction must agree with the reference implementation
    km, T, P = R(16), R(16), R(77)
    m = Mode(hname)
    m.K = ref.derive(hname, km)
    assert m.enc(T, P) == ref.encrypt(hname, km, T, P)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trials", type=int, default=200)
    ap.add_argument("--hash", choices=["sha3", "sha256"], default="sha3")
    a = ap.parse_args()
    check_round_trips(a.hash)
    print(f"Distinguishers of Table 2 (HMAC-{'SHA3-256' if a.hash == 'sha3' else 'SHA-256'}, "
          f"{a.trials} trials each)\n")
    print(f"{'':5} {'variant':38} {'queries':>7} {'variant':>9} {'Concertina':>11}")
    ok = True
    for tag, desc, kw, dist, q in CASES:
        hit_var = sum(dist(Mode(a.hash, **kw), R(16)) for _ in range(a.trials))
        hit_full = sum(dist(Mode(a.hash), R(16)) for _ in range(a.trials))
        print(f"{tag:5} {desc:38} {q:7d} {hit_var:5d}/{a.trials:<3d} {hit_full:6d}/{a.trials}")
        ok &= hit_var == a.trials and hit_full == 0
    print("\nAll distinguishers behave as stated." if ok else "\nUNEXPECTED RESULT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
