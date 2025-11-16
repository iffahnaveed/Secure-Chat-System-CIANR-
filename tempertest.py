#!/usr/bin/env python3
import socket
import json
import base64
import time

HOST = "127.0.0.1"
PORT = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))
print("[*] Connected to server")

# --- 1. Send a normal message ---
normal_msg = {
    "seq": 1,
    "data": base64.b64encode(b"Hello Secure Server").decode(),
    "signature": "valid_signature_for_test"
}
sock.send(json.dumps(normal_msg).encode() + b"\n")
print("[*] Sent normal message")
time.sleep(1)

# --- 2. Tamper with ciphertext (flip bits) ---
tampered_msg = normal_msg.copy()
cipher_bytes = base64.b64decode(tampered_msg["data"])

# Flip some bits
tampered_cipher = bytearray(cipher_bytes)
tampered_cipher[0] ^= 0xFF
tampered_cipher[1] ^= 0xAA

tampered_msg["data"] = base64.b64encode(bytes(tampered_cipher)).decode()

print("[*] Sending tampered message...")
sock.send(json.dumps(tampered_msg).encode() + b"\n")
