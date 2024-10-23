#vernam_cipher.py

import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class VernamCipher:
    @staticmethod
    def encrypt(message, key):
        return bytes([m ^ k for m, k in zip(message, key)])

    @staticmethod
    def decrypt(ciphertext, key):
        return bytes([c ^ k for c, k in zip(ciphertext, key)])

    @staticmethod
    def generate_session_key(shared_key, salt, info):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )
        return hkdf.derive(shared_key)