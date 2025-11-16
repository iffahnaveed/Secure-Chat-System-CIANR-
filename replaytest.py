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

# Send a valid message with seq=1
msg = {
    "seq": 1,
    "data": base64.b64encode(b"Replay Test").decode(),
    "signature": "valid_signature"
}

print("[*] Sending first message...")
sock.send(json.dumps(msg).encode() + b"\n")
time.sleep(1)

# Replay same message again
print("[*] Replaying same message...")
sock.send(json.dumps(msg).encode() + b"\n")
