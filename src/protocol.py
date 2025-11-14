"""
Protocol Message Handlers
Defines message formats and protocol state management
"""

import json
import time
from typing import Dict, Any


class ProtocolMessage:
    """Protocol message builder and parser"""
    
    @staticmethod
    def hello(client_cert_pem, nonce):
        """Client hello message with certificate"""
        return {
            "type": "hello",
            "client_cert": client_cert_pem,
            "nonce": nonce
        }
    
    @staticmethod
    def server_hello(server_cert_pem, nonce):
        """Server hello response with certificate"""
        return {
            "type": "server_hello",
            "server_cert": server_cert_pem,
            "nonce": nonce
        }
    
    @staticmethod
    def register(email, username, pwd_hash, salt):
        """Registration message (encrypted payload)"""
        return {
            "type": "register",
            "email": email,
            "username": username,
            "pwd": pwd_hash,
            "salt": salt
        }
    
    @staticmethod
    def login(email, pwd_hash, nonce):
        """Login message (encrypted payload)"""
        return {
            "type": "login",
            "email": email,
            "pwd": pwd_hash,
            "nonce": nonce
        }
    
    @staticmethod
    def dh_client(g, p, A):
        """Client DH parameters"""
        return {
            "type": "dh_client",
            "g": g,
            "p": p,
            "A": A
        }
    
    @staticmethod
    def dh_server(B):
        """Server DH response"""
        return {
            "type": "dh_server",
            "B": B
        }
    
    @staticmethod
    def chat_message(seqno, timestamp, ciphertext, signature):
        """Encrypted and signed chat message"""
        return {
            "type": "msg",
            "seqno": seqno,
            "ts": timestamp,
            "ct": ciphertext,
            "sig": signature
        }
    
    @staticmethod
    def session_receipt(peer, first_seq, last_seq, transcript_hash, signature):
        """Non-repudiation session receipt"""
        return {
            "type": "receipt",
            "peer": peer,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": signature
        }
    
    @staticmethod
    def ack(status, message=""):
        """Acknowledgment message"""
        return {
            "type": "ack",
            "status": status,
            "message": message
        }
    
    @staticmethod
    def error(error_type, message):
        """Error message"""
        return {
            "type": "error",
            "error": error_type,
            "message": message
        }
    
    @staticmethod
    def encode(msg_dict):
        """Encode message to JSON bytes"""
        return json.dumps(msg_dict).encode('utf-8')
    
    @staticmethod
    def decode(msg_bytes):
        """Decode JSON bytes to message dict"""
        return json.loads(msg_bytes.decode('utf-8'))


class ProtocolState:
    """Manages protocol state machine"""
    
    # States
    INIT = "INIT"
    CERT_EXCHANGED = "CERT_EXCHANGED"
    AUTHENTICATED = "AUTHENTICATED"
    KEY_AGREED = "KEY_AGREED"
    CHATTING = "CHATTING"
    CLOSED = "CLOSED"
    
    def __init__(self):
        self.state = self.INIT
        self.session_key = None
        self.peer_cert = None
        self.peer_public_key = None
        self.seqno_sent = 0
        self.seqno_received = 0
        self.transcript = []
    
    def add_to_transcript(self, seqno, timestamp, ciphertext, signature, peer_fingerprint):
        """Add message to transcript for non-repudiation"""
        entry = f"{seqno}|{timestamp}|{ciphertext}|{signature}|{peer_fingerprint}"
        self.transcript.append(entry)
    
    def get_transcript_hash(self, crypto_utils):
        """Compute SHA-256 hash of transcript"""
        transcript_str = "\n".join(self.transcript)
        return crypto_utils.sha256_hash(transcript_str)
    
    def increment_send_seqno(self):
        """Increment and return sequence number for sending"""
        self.seqno_sent += 1
        return self.seqno_sent
    
    def verify_receive_seqno(self, seqno):
        """
        Verify received sequence number is strictly increasing
        Returns: True if valid, False if replay
        """
        if seqno <= self.seqno_received:
            return False
        self.seqno_received = seqno
        return True


class MessageValidator:
    """Validates protocol messages"""
    
    @staticmethod
    def validate_hello(msg):
        """Validate hello message structure"""
        required = ["type", "client_cert", "nonce"]
        return all(field in msg for field in required) and msg["type"] == "hello"
    
    @staticmethod
    def validate_server_hello(msg):
        """Validate server hello message structure"""
        required = ["type", "server_cert", "nonce"]
        return all(field in msg for field in required) and msg["type"] == "server_hello"
    
    @staticmethod
    def validate_dh_client(msg):
        """Validate DH client message structure"""
        required = ["type", "g", "p", "A"]
        return all(field in msg for field in required) and msg["type"] == "dh_client"
    
    @staticmethod
    def validate_dh_server(msg):
        """Validate DH server message structure"""
        required = ["type", "B"]
        return all(field in msg for field in required) and msg["type"] == "dh_server"
    
    @staticmethod
    def validate_chat_message(msg):
        """Validate chat message structure"""
        required = ["type", "seqno", "ts", "ct", "sig"]
        return all(field in msg for field in required) and msg["type"] == "msg"
    
    @staticmethod
    def validate_timestamp(timestamp, max_age_ms=300000):
        """
        Validate timestamp is recent (within max_age_ms milliseconds)
        Default: 5 minutes
        """
        current_time = int(time.time() * 1000)
        age = abs(current_time - timestamp)
        return age <= max_age_ms
