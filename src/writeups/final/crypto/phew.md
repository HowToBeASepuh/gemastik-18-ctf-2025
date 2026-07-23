---
layout: challenge.njk
title: Phew
category: Crypto
part: Final
author: onta
flag: "GEMASTIK18{tlRgvMsOotJEbKfIzltPgkd9pb070y1t0rBR6gUhljPTDGCYOlQ9ugzj5S0fK4iq}"
flagTeaser: "GEMASTIK18{tlRgvMsOot...}"
description: "A modified Paillier scheme whose decrypt returns an affine transform of the plaintext (α·raw + β) — that leak lets us recover n, factor it, and recover the key."
attachments:
  - { name: chall.py, path: /files/final/phew/chall.py }
  - { name: Pailier.py, path: /files/final/phew/Pailier.py }
  - { name: poc.py, path: /files/final/phew/poc.py }
tags: [paillier, homomorphic, crt, factorization]
---

## Overview

The challenge implements a modified **Paillier** cryptosystem:

```python
class pailier:
    def __init__(self):
        self.primes = [getPrime(512) for _ in range(2)]
        self.n = 1
        self.phi = 1
        self.mul = 1
        for i in range(2):
            self.n *= self.primes[i]
            self.phi *= (self.primes[i] - 1)
        self.n2 = self.n * self.n
        self.g = [pow(random.randrange(1, self.n2), self.primes[i], self.n2) for i in range(2)]
        for x in self.g:
            self.mul = (self.mul * x) % self.n2
        self.miu = inverse(self.L(pow(self.mul, self.phi, self.n2)), self.n)
        self.alpha = [None, None]
        for idx in range(2):
            while True:
                a = random.randrange(2, self.n - 1)
                if GCD(a, self.n) == 1:
                    self.alpha[idx] = a
                    break
        self.beta = [random.randrange(0, self.n), random.randrange(0, self.n)]

    def L(self, val):
        return (val - 1) // self.n

    def encrypt(self, msg: int) -> int:
        r = random.randrange(0, self.n - 1)
        gb = self.g[random.randrange(0, 2)]
        gm = pow(gb, msg, self.n2)
        rn = pow(r, self.n, self.n2)
        return (gm * rn) % self.n2

    def decrypt(self, ct: int) -> int:
        raw = self.L(pow(ct, self.phi, self.n2)) % self.n
        raw = (raw * self.miu) % self.n
        t = pow(ct % self.n, (self.n - 1) // 2, self.n) if (self.n % 2 == 1) else 0
        idx = 0 if t == 1 else 1
        return (self.alpha[idx] * raw + self.beta[idx]) % self.n
```

Main parameters:

- `n = p · q` (product of two 512-bit primes),
- `g = [g0, g1]` — there are **two** generators,
- ciphertext `= g^m · r^n (mod n²)`.

The twist is in `decrypt`: instead of returning the plaintext, it returns an **affine transform**
of it, selecting `idx` by a Legendre-symbol-like test:

```python
t = pow(ct % self.n, (self.n - 1) // 2, self.n) if (self.n % 2 == 1) else 0
idx = 0 if t == 1 else 1
return (self.alpha[idx] * raw + self.beta[idx]) % self.n
```

So `decrypt(c) = (α[idx] · raw + β[idx]) mod n`. That leak is exactly what lets us peel back the
internal structure of the modulus `n`.

## Interface

Connecting to the service gives a menu:

1. `encrypt(m)` → encrypt an arbitrary integer.
2. `bingo(key)` → submit a guessed key (must be the correct 66-byte value).
3. `decrypt(c)` → decrypt a ciphertext.
4. `key?` → returns `Enc(key_int)`.

Our goal is to recover the **key** and submit it via option 2.

## Vulnerability & steps

Since `decrypt` returns `(α[idx]·raw + β[idx]) mod n`, we can use it to recover:

- the modulus `n` from the difference of "cubed" decryptions, and
- the factors of `n` via a GCD leak when we decrypt `encrypt(1)`.

**1. Recover β.** Encrypting `0` gives `Decrypt(0) = (α[idx]·0 + β[idx]) mod n = β[idx] mod n`.

**2. Recover modulus n.** Using the homomorphism, `c^3 = Enc(3m)`, so for the key ciphertext `ck`:

```
d3 = Dec(ck^3) = α·3m + β
d  = Dec(ck)   = α·m + β
d3 − 3·d + 2β ≡ 0 (mod n)
```

Every such `Δ = d3 − 3·d + 2β` is a multiple of `n`, so taking the GCD of many deltas yields `n`.

**3. Factor n.** For several `c1 = encrypt(1)`, compute `alpha = (decrypt(c1) − β) mod n`; then
`gcd(alpha, n)` yields `p` or `q`. Collect until both factors are found.

**4. Split the key ciphertext.** From `Enc(key)`, compute `u = (Dec(c³) − Dec(c)) / 2 (mod n)`.
Depending on which generator was used, `u ≡ 0 (mod p)` ("p-vanishing") or `u ≡ 0 (mod q)`
("q-vanishing"); store these as `up` and `uq`.

**5. Match with the `encrypt(1)` generators.** Find `a_p` (a decryption of `encrypt(1)` divisible
by `p`) and `a_q` (divisible by `q`).

**6. Solve the congruences** and CRT:

```
key ≡ (up · a_p⁻¹) mod p
key ≡ (uq · a_q⁻¹) mod q
```

CRT-combining these gives the `key`; submitting it to option 2 (`bingo`) returns the flag.

## Solution script

```python
#!/usr/bin/env python3
import sys, math
from pwn import context, process, remote

class PwntoolsClient:
    def __init__(self):
        context.log_level = 'INFO'
        self.p = remote('54.169.34.94', 13000)
        self.p.recvuntil(b'> ')

    def encrypt(self, m_int: int) -> int:
        self.p.sendline(b'1'); self.p.recvuntil(b'pt (hex)'); self.p.recvuntil(b'> ')
        self.p.sendline(f'{m_int:x}'.encode()); self.p.recvuntil(b'ct : ')
        ct = int(self.p.recvline().strip().decode(), 16); self.p.recvuntil(b'> '); return ct

    def decrypt(self, c_int: int) -> int:
        self.p.sendline(b'3'); self.p.recvuntil(b'ct (hex)'); self.p.recvuntil(b'> ')
        self.p.sendline(f'{c_int:x}'.encode()); self.p.recvuntil(b'pt : ')
        pt = int(self.p.recvline().strip().decode(), 16); self.p.recvuntil(b'> '); return pt

    def key_ct(self) -> int:
        self.p.sendline(b'4'); self.p.recvuntil(b'ct : ')
        ct = int(self.p.recvline().strip().decode(), 16); self.p.recvuntil(b'> '); return ct

    def bingo(self, key_hex: str) -> str:
        self.p.sendline(b'2'); self.p.recvuntil(b'key (hex)'); self.p.recvuntil(b'> ')
        self.p.sendline(key_hex.encode())
        return self.p.recvuntil(b'> ', drop=True).decode(errors='ignore')

def inv_mod(a, n): return pow(a, -1, n)

def recover_n(cli, beta1, rounds=6):
    G = 0
    for _ in range(rounds):
        ck = cli.key_ct()
        d1 = cli.decrypt(ck)
        d3 = cli.decrypt(pow(ck, 3))
        delta = d3 - 3 * d1 + 2 * beta1
        if delta:
            G = math.gcd(G, abs(delta))
    while G % 2 == 0:
        G //= 2
    return G

def factor_n(cli, n, beta1, tries=40):
    p = q = None
    for _ in range(tries):
        c1 = cli.encrypt(1); d = cli.decrypt(c1)
        a = (d - beta1) % n; g = math.gcd(a, n)
        if 1 < g < n:
            if p is None: p = g
            elif g != p: q = n // p; break
    if p > q: p, q = q, p
    return p, q

def crt_pair(a1, m1, a2, m2):
    inv_m1 = inv_mod(m1 % m2, m2); inv_m2 = inv_mod(m2 % m1, m1)
    n = m1 * m2
    return (a1 * m2 * inv_m2 + a2 * m1 * inv_m1) % n

def solve():
    cli = PwntoolsClient()
    beta1 = cli.decrypt(cli.encrypt(0))            # β for idx = 1
    n = recover_n(cli, beta1, rounds=6)            # modulus from key-ct deltas
    p, q = factor_n(cli, n, beta1)                 # factor via enc(1) leak

    up = uq = None
    for _ in range(30):
        ck = cli.key_ct(); d1 = cli.decrypt(ck); d3 = cli.decrypt(pow(ck, 3))
        u = ((d3 - d1) % n) * inv_mod(2, n) % n
        if up is None and u % p == 0: up = u
        if uq is None and u % q == 0: uq = u
        if up is not None and uq is not None: break

    a_p = a_q = None
    for _ in range(30):
        d = cli.decrypt(cli.encrypt(1)); a = (d - beta1) % n; g = math.gcd(a, n)
        if g == p and a_p is None: a_p = a
        elif g == q and a_q is None: a_q = a
        if a_p is not None and a_q is not None: break

    key_mod_q = (up % q) * inv_mod(a_p % q, q) % q
    key_mod_p = (uq % p) * inv_mod(a_q % p, p) % p
    key_int = crt_pair(key_mod_p, p, key_mod_q, q)
    key_hex = format(key_int, 'x').zfill(132)
    sys.stdout.write(cli.bingo(key_hex))

if __name__ == '__main__':
    solve()
```

Running it recovers the key and prints the flag:

```text
python poc.py
GEMASTIK18{tlRgvMsOotJEbKfIzltPgkd9pb070y1t0rBR6gUhljPTDGCYOlQ9ugzj5S0fK4iq}
```
