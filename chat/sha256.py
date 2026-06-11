import hmac
import hashlib

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def ch(x, y, z):
    return (x & y) ^ ((~x & 0xFFFFFFFF) & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def big_sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def big_sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def small_sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def small_sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

INITIAL_HASHES = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]


BLOCK_SIZE = 64

def sha256_pad(message):
    original_length = len(message) * 8
    
    padded = bytearray(message)
    
    padded.append(0x80)
    
    while(len(padded) * 8) % 512 != 448:
        padded.append(0)
        
    padded += original_length.to_bytes(8, 'big')
    
    return padded

def parse_block(block):
    words = []
    
    for i in range(0, 64, 4):
        word = int.from_bytes(block[i:i+4], 'big')
        words.append(word)
        
    return words

def message_schedule(block):
    W = parse_block(block)
    
    for t in range(16, 64):
        value = (
            small_sigma1(W[t - 2]) +
            W[t - 7] +
            small_sigma0(W[t - 15]) +
            W[t - 16]
        ) & 0xFFFFFFFF
        
        W.append(value)
        
    return W

def compress_block(block, H):
    W = message_schedule(block)
    a, b, c, d, e, f, g, h = H
    for t in range(64):
        T1 = (
            h +
            big_sigma1(e) +
            ch(e, f, g) +
            K[t] +
            W[t]
        ) & 0xFFFFFFFF
        
        T2 = (
            big_sigma0(a) +
            maj(a, b, c)
        ) & 0xFFFFFFFF
        
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF
        
    return [
        (H[0] + a) & 0xFFFFFFFF,
        (H[1] + b) & 0xFFFFFFFF,
        (H[2] + c) & 0xFFFFFFFF,
        (H[3] + d) & 0xFFFFFFFF,
        (H[4] + e) & 0xFFFFFFFF,
        (H[5] + f) & 0xFFFFFFFF,
        (H[6] + g) & 0xFFFFFFFF,
        (H[7] + h) & 0xFFFFFFFF
    ]
    
def sha256(data):
    padded = sha256_pad(data)
        
    H = INITIAL_HASHES.copy()
        
    for i in range(0, len(padded), 64):
        block = padded[i:i+64]
        H = compress_block(block, H)
            
    digest = b''.join(h.to_bytes(4, 'big') for h in H)
        
    return digest
    
def sha256_hex(data):
    return sha256(data).hex()
    
def hmac_sha256(key, message):
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
            
    if len(key) < BLOCK_SIZE:
        key += bytes(BLOCK_SIZE - len(key))
            
    ipad = bytes([0x36] * BLOCK_SIZE)
    opad = bytes([0x5c] * BLOCK_SIZE)
        
    key_xor_ipad = bytes(k ^ i for k, i in zip(key, ipad))
    key_xor_opad = bytes(k ^ o for k, o in zip(key, opad))
        
    inner_hash = sha256(key_xor_ipad + message)
        
    return sha256(key_xor_opad + inner_hash)
    
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))
    
def pbkdf2_sha256(password, salt, iterations, dklen):
    hlen = 32
        
    num_blocks = (dklen + hlen - 1) // hlen
        
    derived_key = b''
        
    for block_index in range(1, num_blocks + 1):
            
        U = hmac_sha256(
            password,
            salt + block_index.to_bytes(4, 'big')
        )
            
        T = U
            
        for _ in range(iterations - 1):
            U = hmac_sha256(password, U)
            T = xor_bytes(T, U)
                
        derived_key += T
            
    return derived_key[:dklen]
'''
if __name__ == "__main__":
    #Teste do padding
    msg = b"abc"

    padded = sha256_pad(msg)

    print(len(padded))  # 64 bytes
    print(padded.hex())
    
    #Teste rápido parse_block
    #Resultado esperado:
    #0x10203
    #0x4050607
    
    block = bytes(range(64))

    words = parse_block(block)

    print(hex(words[0]))
    print(hex(words[1]))
    
    #Teste simples message_schedule
    #Resultado esperado:
    #64
    msg = b"abc"

    padded = sha256_pad(msg)

    block = padded[:64]

    W = message_schedule(block)

    print(len(W))
    
    for i in range(20):
        print(f"W[{i}] = {hex(W[i])}")
        
    #Primeiro teste OFICIAL: Vetor NIST
    #Resultado esperado:
    #ba7816bf8f01cfea414140de5dae2223
    #b00361a396177a9cb410ff61f20015ad
    print(sha256_hex(b"abc"))
    
    #Segundo teste: String vazia
    #Resultado esperado:
    #e3b0c44298fc1c149afbf4c8996fb924
    #27ae41e4649b934ca495991b7852b855
    print(sha256_hex(b""))
    
    #Teste comparativo com hashlib
    data = b"Mensagem de teste"
    
    manual = sha256_hex(data)
    oficial = hashlib.sha256(data).hexdigest()
    
    print(manual)
    print(oficial)
    
    assert manual == oficial
    
    print("SHA-256 OK")
    
    #Teste comparativo com hmac
    
    key = b"senha"
    msg = b"mensagem"
    
    manual = hmac_sha256(key, msg).hex()
    
    oficial = hmac.new(
        key,
        msg,
        hashlib.sha256
    ).hexdigest()
    
    print(manual)
    print(oficial)
    
    assert manual == oficial
    
    print("HMAC OK")
    
    #Teste PBKDF2
    
    password = b"senha123"
    salt = b"salteste"
    
    manual = pbkdf2_sha256(
        password,
        salt,
        1000,
        32
    )
    
    oficial = hashlib.pbkdf2_hmac(
        'sha256',
        password,
        salt,
        1000,
        32
    )
    
    print(manual.hex())
    print(oficial.hex())
    
    assert manual == oficial
    
    print("PBKDF2 OK")
    '''