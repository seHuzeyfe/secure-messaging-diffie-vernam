Secure Messaging Project : Encrypted Messaging System with Diffie-Hellman Key Exchange and Vernam Cipher

This project implements a secure messaging system where two clients communicate over TCP using encrypted messages. It uses the Diffie-Hellman key exchange to establish a shared secret key between the clients without transmitting it directly. This shared key is then used to derive unique session keys for each message using HKDF (HMAC-based Key Derivation Function). The messages are encrypted and decrypted with a Vernam cipher, ensuring confidentiality. Additionally, a port sniffer monitors specific traffic, capturing encrypted communications for analysis.

Program execution steps

-Run Client B (client_b.py) - it is act like the server
	
-Run Client A (client_a.py) - it is client that connect the port that listen by Client B
	- After connection established key exchange process will start.
	- Messages can be send from both side.

- To test the system if messages actually crypted or not , there is port listener script (port_listener.py)
-Enter option '6' , since it is a locale network.
-It's basically works like Wireshark , but only listens a single port and logs the data that read on the port.

-To execute it open a terminal as administrator then go to project directory , run the file > python port_listener.py
-This program will listen the port and read the data flow on the port , will try to decode the datas. 

Required Libraries :

- pip install cryptography
- pip install scapy



