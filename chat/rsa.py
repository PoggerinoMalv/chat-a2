import random
import sha256
import os
import json

def is_probable_prime(n, k=10):

    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23]
    if n in small_primes:
        return True

    for p in small_primes:
        if n % p == 0:
            return False

    d = n - 1
    r = 0

    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_prime(min_value, max_value):
    while True:
        p = random.randint(min_value, max_value)
        if p % 2 == 0:
            continue
        if is_probable_prime(p):
            return p

def modexp(base, exp, mod):
    result = 1
    base %= mod

    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        
        base = (base * base) % mod
        exp >>= 1

    return result

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    
    g, x1, y1 = egcd(b % a, a)
    return (g, y1 - (b // a) * x1, x1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception("Sem inverso.")
    return x % m

def generate_keys():
    p = generate_prime(2**511, 2**512)
    q = generate_prime(2**511, 2**512)

    while q == p:
        q = generate_prime(2**511, 2**512)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    for candidate in [65537, 17, 5, 3]:
        if phi % candidate != 0:
            e = candidate
            break

    d = modinv(e, phi)

    return (e, n), (d, n)

def save_key(key, filename):
    exponent, modulus = key

    with open(filename, "w") as f:
        json.dump({
            "exponent": str(exponent),
            "modulus": str(modulus)
        }, f)

def load_key(filename):
    with open(filename, "r") as f:
        data = json.load(f)

    return (
        int(data["exponent"]),
        int(data["modulus"])
    )

def split_bytes(data, block_size):
    return [
        data[i:i+block_size]
        for i in range(0, len(data), block_size)
    ]

def encrypt_key(aes_key, pubkey):
    e, n = pubkey
    m = int.from_bytes(aes_key, "big")

    if m >= n:
        raise ValueError("Key maior que RSA modulus")

    return modexp(m, e, n)

def decrypt_key(cipher, privkey):
    d, n = privkey
    m = modexp(cipher, d, n)

    k = (n.bit_length() + 7) // 8
    return m.to_bytes(k, "big").lstrip(b"\x00")[:16]

def sign(data, private_key):
    digest = sha256.sha256(data)

    d, n = private_key

    h = int.from_bytes(digest, 'big') % n

    return modexp(h, d, n)

def verify(data, signature, public_key):

    digest = sha256.sha256(data)

    e, n = public_key

    expected = int.from_bytes(digest, 'big') % n

    received = modexp(signature, e, n)

    return expected == received

def bytes_to_int(b):
    return int.from_bytes(b, "big")

def int_to_bytes(i):
    if i == 0:
        return b"\x00"
    return i.to_bytes((i.bit_length() + 7) // 8, "big")

'''
pub, priv = generate_keys()

key = os.urandom(16)

cipher = encrypt_bytes(key, pub)

plain = decrypt_bytes(cipher, priv)

print(key)
print(plain[:16])

key = os.urandom(16)

cipher = encrypt_bytes(key, pub)

plain = decrypt_bytes(cipher, priv)

print(len(key))
print(len(plain))

print(key.hex())
print(plain.hex())

pub, priv = generate_keys()

key = os.urandom(16)

cipher = encrypt_bytes(key, pub)

plain = decrypt_bytes(cipher, priv)

assert key == plain
'''
