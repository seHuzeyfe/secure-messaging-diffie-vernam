#client.py

import socket
import threading
import os
from diffie_hellman import DiffieHellman
from vernam_cipher import VernamCipher

class Client:
    def __init__(self, host, port, is_server=False):
        self.host = host
        self.port = port
        self.is_server = is_server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key = None
        self.message_counter = 0

    def connect(self):
        if self.is_server:
            self.socket.bind((self.host, self.port))
            self.socket.listen(1)
            print(f"Server listening on {self.host}:{self.port}")
            self.conn, addr = self.socket.accept()
            print(f"Connection from {addr}")
        else:
            self.socket.connect((self.host, self.port))
            self.conn = self.socket
            print("Connected to server")

    def perform_key_exchange(self):
        dh = DiffieHellman()
        
        if self.is_server:
            # Server generates parameters and sends them to the client
            parameters = dh.generate_parameters()
            param_bytes = dh.serialize_parameters(parameters)
            self.conn.sendall(len(param_bytes).to_bytes(4, 'big') + param_bytes)
        else:
            # Client receives parameters from the server
            param_size = int.from_bytes(self.conn.recv(4), 'big')
            param_bytes = self.conn.recv(param_size)
            parameters = dh.deserialize_parameters(param_bytes)

        private_key = dh.generate_private_key(parameters)
        public_key = private_key.public_key()

        # Exchange public keys
        public_bytes = dh.get_public_key_bytes(public_key)
        self.conn.sendall(len(public_bytes).to_bytes(4, 'big') + public_bytes)

        key_size = int.from_bytes(self.conn.recv(4), 'big')
        peer_public_bytes = self.conn.recv(key_size)
        peer_public_key = dh.load_public_key(peer_public_bytes)

        # Compute shared key
        self.shared_key = dh.compute_shared_key(private_key, peer_public_key)
        print("Key exchange completed")

    def send_message(self):
        while True:
            message = input(f"{'Client B' if self.is_server else 'Client A'}: ")
            if message.lower() == 'exit':
                break

            salt = os.urandom(16)
            info = f"message{self.message_counter}".encode()
            session_key = VernamCipher.generate_session_key(self.shared_key, salt, info)

            encrypted_message = VernamCipher.encrypt(message.encode(), session_key)
            self.conn.sendall(len(salt).to_bytes(4, 'big') + salt + encrypted_message)

            self.message_counter += 1

    def receive_message(self):
        while True:
            try:
                salt_size = int.from_bytes(self.conn.recv(4), 'big')
                salt = self.conn.recv(salt_size)
                encrypted_message = self.conn.recv(1024)

                info = f"message{self.message_counter}".encode()
                session_key = VernamCipher.generate_session_key(self.shared_key, salt, info)

                decrypted_message = VernamCipher.decrypt(encrypted_message, session_key).decode()
                print(f"\n{'Client A' if self.is_server else 'Client B'}: {decrypted_message}")

                self.message_counter += 1
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def run(self):
        self.connect()
        self.perform_key_exchange()

        receive_thread = threading.Thread(target=self.receive_message, daemon=True)
        receive_thread.start()

        self.send_message()