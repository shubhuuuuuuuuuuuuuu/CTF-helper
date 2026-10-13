from __future__ import annotations

import math


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0: return (abs(a), 1 if a >= 0 else -1, 0)
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a: int, modulus: int) -> int:
    if modulus <= 1: raise ValueError("Modulus must be greater than one")
    g, x, _ = extended_gcd(a, modulus)
    if g != 1: raise ValueError("Modular inverse does not exist")
    return x % modulus


def rsa_inspect(n: int, e: int, c: int, factor_limit: int = 1_000_000) -> dict[str, int | str]:
    if n <= 1 or e <= 0 or c < 0 or c >= n: raise ValueError("Invalid RSA parameters: require n > 1, e > 0, and 0 <= c < n")
    p = 2
    while p <= min(math.isqrt(n), factor_limit) and n % p: p += 1
    if p <= min(math.isqrt(n), factor_limit):
        q = n // p
        if not _prime_within_bound(q, factor_limit):
            return {"status": "factor not proven prime", "message": "The cofactor is composite or could not be proven prime within the configured bound; RSA decryption was skipped."}
        phi = (p-1)*(q-1)
        d = mod_inverse(e, phi)
        return {"p": p, "q": q, "d": d, "plaintext_integer": pow(c, d, n)}
    return {"status": "not factored", "message": f"No factor found up to configured bound {factor_limit}."}


def _prime_within_bound(number: int, limit: int) -> bool:
    """Prove primality by trial division only when sqrt(number) is within the bound."""
    if number < 2: return False
    if number % 2 == 0: return number == 2
    root = math.isqrt(number)
    if root > limit: return False
    divisor = 3
    while divisor <= root:
        if number % divisor == 0: return False
        divisor += 2
    return True
