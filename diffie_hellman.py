#diffie_hellman.py

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

class DiffieHellman:
    @staticmethod
    def generate_parameters():
        return dh.generate_parameters(generator=2, key_size=2048)

    @staticmethod
    def serialize_parameters(parameters):
        return parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )

    @staticmethod
    def deserialize_parameters(parameter_bytes):
        return serialization.load_pem_parameters(parameter_bytes)

    @staticmethod
    def generate_private_key(parameters):
        return parameters.generate_private_key()

    @staticmethod
    def get_public_key_bytes(public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    @staticmethod
    def load_public_key(public_key_bytes):
        return serialization.load_pem_public_key(public_key_bytes)

    @staticmethod
    def compute_shared_key(private_key, peer_public_key):
        return private_key.exchange(peer_public_key)