import aespuro
import rsa
import json
import os


def create_packet(plaintext, sender_name, sender_private_key, receiver_public_key):

    aes_key = os.urandom(16)
    iv = os.urandom(16)

    aes = aespuro.AES(aes_key)

    padded = aespuro.pkcs7_pad(plaintext.encode("utf-8"))
    ciphertext = aespuro.aes_encrypt_cbc(padded, aes, iv)

    encrypted_key = rsa.encrypt_key(aes_key, receiver_public_key)

    to_sign = iv + ciphertext
    signature = rsa.sign(to_sign, sender_private_key)

    return {
        "sender": sender_name,
        "encrypted_key": encrypted_key,
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
        "signature": str(signature)
    }


def read_packet(packet, receiver_private_key, sender_public_key):

    iv = bytes.fromhex(packet["iv"])
    ciphertext = bytes.fromhex(packet["ciphertext"])
    signature = int(packet["signature"])

    to_sign = iv + ciphertext

    if not rsa.verify(to_sign, signature, sender_public_key):
        raise ValueError("Assinatura inválida")

    aes_key = rsa.decrypt_key(packet["encrypted_key"], receiver_private_key)
    aes = aespuro.AES(aes_key)

    padded = aespuro.aes_decrypt_cbc(ciphertext, aes, iv)
    plaintext = aespuro.pkcs7_unpad(padded)

    return plaintext.decode("utf-8")