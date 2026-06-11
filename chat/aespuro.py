import os
import hashlib
import sha256

# ARITMÉTICA

def xtime(a):
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return p

def multiplicative_inverse(byte):
    if byte == 0:
        return 0
    for i in range(1, 256):
        if gf_mul(byte, i) == 1:
            return i   
    return 0

# S-BOX

def affine_transform(byte):
    b = byte
    res = b ^ ((b << 1) | (b >> 7)) & 0xFF
    res ^= ((b << 2) | (b >> 6)) & 0xFF
    res ^= ((b << 3) | (b >> 5)) & 0xFF
    res ^= ((b << 4) | (b >> 4)) & 0xFF
    res ^= 0x63
    return res & 0xFF

s_box = []
for i in range(256):
    inv = multiplicative_inverse(i)
    s_box.append(affine_transform(inv))

inv_s_box = [0] * 256
for i in range(256):
    inv_s_box[s_box[i]] = i

# KEY EXPANSION

Rcon = [0x01, 0x02, 0x04, 0x08, 0x10,
        0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D, 0x9A]

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [s_box[b] for b in word]

def key_expansion(key):
    key_symbols = list(key)

    Nk = len(key) // 4
    Nr = Nk + 6

    w = [key_symbols[i:i+4] for i in range(0, 4*Nk, 4)]

    for i in range(Nk, 4*(Nr+1)):
        temp = w[i-1].copy()

        if i % Nk == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= Rcon[(i // Nk) - 1]
        elif Nk > 6 and i % Nk == 4:
            temp = sub_word(temp)

        new_word = [w[i-Nk][j] ^ temp[j] for j in range(4)]
        w.append(new_word)

    return w

# CORE

# HELPER
def copy_state(state):
    return [row.copy() for row in state]

def block_to_matrix(block):
    return [[block[row + 4*col] for col in range(4)] for row in range(4)]

def matrix_to_block(state):
    return bytes([state[row][col] for col in range(4) for row in range(4)])

#FORWARD

def sub_bytes(state):
    new_state = copy_state(state)
    for row in range(4):
        for col in range(4):
            new_state[row][col] = s_box[new_state[row][col]]
    return new_state

def shift_rows(state):
    new_state = copy_state(state)

    for row in range(4):
        new_state[row] = new_state[row][row:] + new_state[row][:row]

    return new_state

def mix_single_column(col):
    a0, a1, a2, a3 = col
    b0 = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
    b1 = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
    b2 = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
    b3 = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)

    return [b0, b1, b2, b3]

def mix_columns(state):
    new_state = copy_state(state)

    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = mix_single_column(column)

        for row in range(4):
            new_state[row][col] = mixed[row]

    return new_state

def add_round_key(state, round_key):
    new_state = copy_state(state)

    for row in range(4):
        for col in range(4):
            new_state[row][col] ^= round_key[row][col]

    return new_state

#INVERSE

def inv_sub_bytes(state):
    new_state = copy_state(state)

    for row in range(4):
        for col in range(4):
            new_state[row][col] = inv_s_box[new_state[row][col]]

    return new_state

def inv_shift_rows(state):
    new_state = copy_state(state)

    for row in range(4):
        new_state[row] = new_state[row][-row:] + new_state[row][:-row]

    return new_state

def inv_mix_single_column(col):
    a0, a1, a2, a3 = col

    return [
        gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9),
        gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13),
        gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11),
        gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)
    ]

def inv_mix_columns(state):
    new_state = copy_state(state)

    for col in range(4):
        column = [state[row][col] for row in range(4)]
        mixed = inv_mix_single_column(column)

        for row in range(4):
            new_state[row][col] = mixed[row]

    return new_state

# CLASSE AES

class AES:
    def __init__(self, key):
        self.key = key
        self.Nk = len(key) // 4
        self.Nr = self.Nk + 6
        self.w = key_expansion(key)

    def get_round_key(self, round_num):
        return [[self.w[4*round_num + col][row] for col in range(4)] for row in range(4)]
    
    def encrypt_block(self, block):
        state = block_to_matrix(block)

        state = add_round_key(state, self.get_round_key(0))

        for round_num in range(1, self.Nr):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.get_round_key(round_num))
        
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.get_round_key(self.Nr))

        return matrix_to_block(state)
    
    def decrypt_block(self, block):
        state = block_to_matrix(block)

        state = add_round_key(state, self.get_round_key(self.Nr))

        for round_num in range(self.Nr - 1, 0, -1):
            state = inv_shift_rows(state)
            state = inv_sub_bytes(state)
            state = add_round_key(state, self.get_round_key(round_num))
            state = inv_mix_columns(state)

        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, self.get_round_key(0))

        return matrix_to_block(state)
    
# CBC
    
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def split_blocks(data, block_size=16):
    return [data[i:i+block_size] for i in range(0, len(data), block_size)]

def aes_encrypt_cbc(plaintext, aes, iv):
    blocks = split_blocks(plaintext)
    encrypted_blocks = []

    previous = iv

    for block in blocks:
        xored = xor_bytes(block, previous)
        encrypted = aes.encrypt_block(xored)

        encrypted_blocks.append(encrypted)
        previous = encrypted

    return b''.join(encrypted_blocks)

def aes_decrypt_cbc(ciphertext, aes, iv):
    blocks = split_blocks(ciphertext)
    decrypted_blocks = []

    previous = iv

    for block in blocks:
        decrypted = aes.decrypt_block(block)
        plain = xor_bytes(decrypted, previous)

        decrypted_blocks.append(plain)
        previous = block

    return b''.join(decrypted_blocks)

# UTILIDADES

def derive_key(password, salt, iterations=100000, dklen=16):
    return sha256.pbkdf2_sha256(
        password.encode(),
        salt,
        iterations,
        dklen
    )

def pkcs7_pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def pkcs7_unpad(data):
    padding_len = data[-1]
    if padding_len < 1 or padding_len > 16:
        raise ValueError("Padding inválido!")
    
    if data[-padding_len:] != bytes([padding_len] * padding_len):
        raise ValueError("Padding corrompido!")
    
    return data[:-padding_len]

def read_file(path):
    with open(path, "rb") as f:
        return f.read()
    
def write_file(path, data):
    with open(path, "wb") as f:
        f.write(data)

# TESTES

def encrypt_file(input_path, output_path, password):
    data = read_file(input_path)

    salt = os.urandom(16)
    key = derive_key(password, salt)

    iv = os.urandom(16)

    aes = AES(key)

    padded = pkcs7_pad(data)
    cipher = aes_encrypt_cbc(padded, aes, iv)

    write_file(output_path, salt + iv + cipher)

def decrypt_file(input_path, output_path, password):
    data = read_file(input_path)
    salt = data[:16]
    iv = data[16:32]
    cipher = data[32:]

    key = derive_key(password, salt)

    aes = AES(key)

    padded = aes_decrypt_cbc(cipher, aes, iv)
    plain = pkcs7_unpad(padded)

    write_file(output_path, plain)

def aes_test_roundtrip(key_size):
    password = "senha_teste"
    data = b'Mensagem secreta 123'

    salt = os.urandom(16)
    key = derive_key(password, salt, dklen=key_size)

    iv = os.urandom(16)

    aes = AES(key)

    padded = pkcs7_pad(data)

    cipher = aes_encrypt_cbc(padded, aes, iv)
    decrypted = aes_decrypt_cbc(cipher, aes, iv)

    plain = pkcs7_unpad(decrypted)

    assert plain == data, f'Erro no AES-{key_size*8}'
    print(f'AES-{key_size*8} OK')

def aes_testfile_roundtrip(input_path, dklen):
    password = "senha_teste"

    data = read_file(input_path)

    salt = os.urandom(16)
    key = derive_key(password, salt, dklen=dklen)

    iv = os.urandom(16)

    aes = AES(key)

    padded = pkcs7_pad(data)
    cipher = aes_encrypt_cbc(padded, aes, iv)

    decrypted_padded = aes_decrypt_cbc(cipher, aes, iv)
    plain = pkcs7_unpad(decrypted_padded)

    assert plain == data, 'Erro: arquivo não bate após decrypt'
    print(f'Teste de arquivo AES-{dklen*8} OK.')
'''
if __name__ == "__main__":
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    aes = AES(key)
    cipher = aes.encrypt_block(plaintext)
    print(cipher.hex()) 

    aes_test_roundtrip(16)
    aes_test_roundtrip(24)
    aes_test_roundtrip(32)
    aes_testfile_roundtrip('teste.txt', 16)
    aes_testfile_roundtrip('teste.txt', 24)
    aes_testfile_roundtrip('teste.txt', 32)

    password = "senha123"

    input_file = "teste.txt"

    enc_file = "teste.enc"
    dec_file = "teste_decrypt.txt"

    encrypt_file(input_file, enc_file, password)

    decrypt_file(enc_file, dec_file, password)

    print("Teste concluído!")
'''