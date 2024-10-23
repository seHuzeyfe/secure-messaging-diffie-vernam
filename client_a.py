#client_a.py

from client import Client

if __name__ == "__main__":
    client = Client('127.0.0.1', 14580)
    client.run()