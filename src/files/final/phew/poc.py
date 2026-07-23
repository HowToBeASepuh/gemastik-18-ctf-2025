#!/usr/bin/env python3

import sys
import math
from pwn import context, process, remote
    

class PwntoolsClient:
    def __init__(self):
        context.log_level = 'error'
        self.p = remote('54.169.34.94', 13000)
        # self.p = process([sys.executable, '-u', './chall.py'])
        # Read initial menu prompt
        self.p.recvuntil(b'> ')

    def encrypt(self, m_int: int) -> int:
        self.p.sendline(b'1')
        self.p.recvuntil(b'pt (hex)')
        self.p.recvuntil(b'> ')
        self.p.sendline(f'{m_int:x}'.encode())
        self.p.recvuntil(b'ct : ')
        ct_hex = self.p.recvline().strip()
        ct = int(ct_hex.decode(), 16)
        # consume next prompt
        self.p.recvuntil(b'> ')
        return ct

    def decrypt(self, c_int: int) -> int:
        self.p.sendline(b'3')
        self.p.recvuntil(b'ct (hex)')
        self.p.recvuntil(b'> ')
        self.p.sendline(f'{c_int:x}'.encode())
        self.p.recvuntil(b'pt : ')
        pt_hex = self.p.recvline().strip()
        pt = int(pt_hex.decode(), 16)
        # consume next prompt
        self.p.recvuntil(b'> ')
        return pt

    def key_ct(self) -> int:
        self.p.sendline(b'4')
        self.p.recvuntil(b'ct : ')
        ct_hex = self.p.recvline().strip()
        ct = int(ct_hex.decode(), 16)
        # consume next prompt
        self.p.recvuntil(b'> ')
        return ct

    def bingo(self, key_hex: str) -> str:
        self.p.sendline(b'2')
        self.p.recvuntil(b'key (hex)')
        self.p.recvuntil(b'> ')
        self.p.sendline(key_hex.encode())
        out = self.p.recvuntil(b'> ', drop=True).decode(errors='ignore')
        return out


def inv_mod(a: int, n: int) -> int:
    if math.gcd(a, n) != 1:
        raise ValueError('non-invertible')
    return pow(a, -1, n)


def recover_n(cli: PwntoolsClient, beta1: int, rounds: int = 6) -> int:
    G = 0
    for _ in range(rounds):
        ck = cli.key_ct()
        d1 = cli.decrypt(ck)
        d3 = cli.decrypt(pow(ck, 3))
        delta = d3 - 3 * d1 + 2 * beta1
        if delta:
            G = math.gcd(G, abs(delta))
    if G == 0:
        raise RuntimeError('failed to compute modulus')
    # Normalize: remove small factor 2 if present (n should be odd)
    while G % 2 == 0:
        G //= 2
    return G


def factor_n(cli: PwntoolsClient, n: int, beta1: int, tries: int = 40):
    p = q = None
    for _ in range(tries):
        c1 = cli.encrypt(1)
        d = cli.decrypt(c1)
        a = (d - beta1) % n
        g = math.gcd(a, n)
        if 1 < g < n:
            if p is None:
                p = g
            elif g != p:
                q = n // p if g == p else g
                break
    if p is None or q is None or p * q != n:
        # try a few more
        for _ in range(tries):
            c1 = cli.encrypt(1)
            d = cli.decrypt(c1)
            a = (d - beta1) % n
            g = math.gcd(a, n)
            if 1 < g < n and g != p:
                p, q = min(g, n // g), max(g, n // g)
                break
    if p is None or q is None or p * q != n:
        raise RuntimeError('failed to factor n')
    if p > q:
        p, q = q, p
    return p, q


def crt_pair(a1, m1, a2, m2):
    # Solve x ≡ a1 (mod m1), x ≡ a2 (mod m2)
    inv_m1 = inv_mod(m1 % m2, m2)
    inv_m2 = inv_mod(m2 % m1, m1)
    n = m1 * m2
    x = (a1 * m2 * inv_m2 + a2 * m1 * inv_m1) % n
    return x


def solve():
    cli = PwntoolsClient()

    # beta for idx=1
    c0 = cli.encrypt(0)
    beta1 = cli.decrypt(c0)

    # recover modulus n via key ciphertext deltas
    n = recover_n(cli, beta1, rounds=6)

    # factor n using enc(1) leak
    p, q = factor_n(cli, n, beta1)

    # compute u = alpha1 * key using one key ciphertext
    # and get both generator types so we can solve key mod p and mod q
    up = None  # u from key ct whose u % p == 0 (p-vanishing type)
    uq = None  # u from key ct whose u % q == 0 (q-vanishing type)
    for _ in range(10):
        ck = cli.key_ct()
        d1 = cli.decrypt(ck)
        d3 = cli.decrypt(pow(ck, 3))
        u = (d3 - d1) % n
        u = (u * inv_mod(2, n)) % n  # u = alpha[idx]*kappa_type*key
        if up is None and u % p == 0:
            up = u
        if uq is None and u % q == 0:
            uq = u
        if up is not None and uq is not None:
            break
    if up is None or uq is None:
        # try a few more
        for _ in range(20):
            ck = cli.key_ct()
            d1 = cli.decrypt(ck)
            d3 = cli.decrypt(pow(ck, 3))
            u = (d3 - d1) % n
            u = (u * inv_mod(2, n)) % n
            if up is None and u % p == 0:
                up = u
            if uq is None and u % q == 0:
                uq = u
            if up is not None and uq is not None:
                break
    if up is None or uq is None:
        raise RuntimeError('failed to obtain both key ciphertext types')

    # obtain a_p and a_q from encrypt(1) matching each generator type
    a_p = None  # divisible by p, invertible mod q
    a_q = None  # divisible by q, invertible mod p
    for _ in range(30):
        c1 = cli.encrypt(1)
        d = cli.decrypt(c1)
        a = (d - beta1) % n
        g = math.gcd(a, n)
        if g == p and a_p is None:
            a_p = a
        elif g == q and a_q is None:
            a_q = a
        if a_p is not None and a_q is not None:
            break
    if a_p is None or a_q is None:
        raise RuntimeError('failed to obtain both generator types for enc(1)')

    # Solve key residues
    key_mod_q = (up % q) * inv_mod(a_p % q, q) % q
    key_mod_p = (uq % p) * inv_mod(a_q % p, p) % p

    key_int = crt_pair(key_mod_p, p, key_mod_q, q)
    key_hex = format(key_int, 'x').zfill(132)

    out = cli.bingo(key_hex)
    # print whatever we got (flag or nope)
    sys.stdout.write(out)


if __name__ == '__main__':
    solve()
