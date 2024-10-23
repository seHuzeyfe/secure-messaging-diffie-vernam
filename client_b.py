#client_b.py

from client import Client

if __name__ == "__main__":
    server = Client('127.0.0.1', 14580, is_server=True)
    server.run()