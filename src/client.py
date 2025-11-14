"""
Secure Chat Client
Connects to server with mutual authentication and encrypted messaging
"""

import socket
import json
import time
import os
import base64
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from crypto_utils import CryptoUtils, DH_P, DH_G
from protocol import ProtocolMessage, ProtocolState, MessageValidator


class SecureChatClient:
    """Secure chat client implementation"""
    
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.crypto = CryptoUtils()
        self.socket = None
        self.state = ProtocolState()
        
        # Load client certificate and private key
        self.client_cert = self.crypto.load_certificate('certs/client_cert.pem')
        self.client_key = self.crypto.load_private_key('certs/client_key.pem')
        
        # Load CA certificate for verification
        self.ca_cert = self.crypto.load_certificate('certs/ca_cert.pem')
        
        # Get client cert as PEM string
        self.client_cert_pem = self.client_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Create transcripts directory
        os.makedirs('transcripts', exist_ok=True)
        
        print(f"[*] Client initialized")
        print(f"[*] Client certificate loaded: CN={self.client_cert.subject.rfc4514_string()}")
    
    def connect(self):
        """Connect to server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        print(f"[+] Connected to {self.host}:{self.port}")
    
    def exchange_certificates(self):
        """Phase 1: Certificate exchange and mutual authentication"""
        print("\n[*] Phase 1: Certificate Exchange")
        
        # Send client hello
        client_nonce = self.crypto.generate_nonce()
        hello_msg = ProtocolMessage.hello(self.client_cert_pem, client_nonce)
        self.socket.send(ProtocolMessage.encode(hello_msg))
        
        # Receive server hello
        data = self.socket.recv(8192)
        server_hello = ProtocolMessage.decode(data)
        
        if server_hello['type'] == 'error':
            print(f"[!] Server rejected certificate: {server_hello['message']}")
            return False
        
        if not MessageValidator.validate_server_hello(server_hello):
            print("[!] Invalid server hello")
            return False
        
        # Load and verify server certificate
        server_cert_pem = server_hello['server_cert']
        server_cert = x509.load_pem_x509_certificate(
            server_cert_pem.encode('utf-8'),
            default_backend()
        )
        
        is_valid, error_msg = self.crypto.verify_certificate(server_cert, self.ca_cert)
        if not is_valid:
            print(f"[!] BAD_CERT: {error_msg}")
            return False
        
        print(f"[+] Server certificate verified: CN={server_cert.subject.rfc4514_string()}")
        self.state.peer_cert = server_cert
        self.state.peer_public_key = server_cert.public_key()
        self.state.state = ProtocolState.CERT_EXCHANGED
        
        return True
    
    def temporary_dh_exchange(self):
        """Phase 2: Temporary DH for registration/login encryption"""
        print("\n[*] Phase 2: Temporary DH Exchange")
        
        # Generate DH keypair
        client_dh_private, client_dh_public = self.crypto.generate_dh_keypair()
        
        # Send DH parameters
        dh_msg = ProtocolMessage.dh_client(DH_G, DH_P, client_dh_public)
        self.socket.send(ProtocolMessage.encode(dh_msg))
        
        # Receive server DH response
        data = self.socket.recv(4096)
        dh_response = ProtocolMessage.decode(data)
        
        if not MessageValidator.validate_dh_server(dh_response):
            print("[!] Invalid DH response")
            return None
        
        # Compute shared secret and derive AES key
        server_dh_public = dh_response['B']
        shared_secret = self.crypto.compute_dh_shared_secret(client_dh_private, server_dh_public)
        temp_aes_key = self.crypto.derive_aes_key(shared_secret)
        
        print("[+] Temporary session key established")
        return temp_aes_key
    
    def register(self, temp_aes_key):
        """Register new user"""
        print("\n=== User Registration ===")
        email = input("Email: ")
        username = input("Username: ")
        password = input("Password: ")
        
        # Generate random salt
        salt = self.crypto.generate_salt()
        
        # Compute salted password hash
        pwd_hash = self.crypto.sha256_hash(salt + password.encode('utf-8'))
        
        # Create registration message
        reg_msg = ProtocolMessage.register(
            email,
            username,
            base64.b64encode(salt + password.encode('utf-8')).decode('utf-8'),
            base64.b64encode(salt).decode('utf-8')
        )
        
        # Encrypt and send
        encrypted = self.crypto.aes_encrypt(ProtocolMessage.encode(reg_msg), temp_aes_key)
        self.socket.send(ProtocolMessage.encode({"payload": encrypted}))
        
        # Receive response
        data = self.socket.recv(4096)
        response = ProtocolMessage.decode(data)
        decrypted = self.crypto.aes_decrypt(response['payload'], temp_aes_key)
        result = ProtocolMessage.decode(decrypted)
        
        if result['type'] == 'ack' and result['status'] == 'success':
            print(f"[+] {result['message']}")
            return True, username
        else:
            print(f"[!] Registration failed: {result.get('message', 'Unknown error')}")
            return False, None
    
    def login(self, temp_aes_key):
        """Login existing user"""
        print("\n=== User Login ===")
        email = input("Email: ")
        password = input("Password: ")
        
        # For login, we need to get the salt from server first
        # In this simplified version, we'll send a hash that server will recompute
        # Generate a temporary salt for transmission (server will use stored salt)
        temp_salt = self.crypto.generate_salt()
        
        # Create login message
        login_nonce = self.crypto.generate_nonce()
        login_msg = ProtocolMessage.login(
            email,
            base64.b64encode(temp_salt + password.encode('utf-8')).decode('utf-8'),
            login_nonce
        )
        
        # Encrypt and send
        encrypted = self.crypto.aes_encrypt(ProtocolMessage.encode(login_msg), temp_aes_key)
        self.socket.send(ProtocolMessage.encode({"payload": encrypted}))
        
        # Receive response
        data = self.socket.recv(4096)
        response = ProtocolMessage.decode(data)
        decrypted = self.crypto.aes_decrypt(response['payload'], temp_aes_key)
        result = ProtocolMessage.decode(decrypted)
        
        if result['type'] == 'ack' and result['status'] == 'success':
            print(f"[+] {result['message']}")
            return True, email.split('@')[0]  # Use email prefix as username
        else:
            print(f"[!] Login failed: {result.get('message', 'Unknown error')}")
            return False, None
    
    def chat_session_dh(self):
        """Phase 4: Establish chat session key"""
        print("\n[*] Phase 4: Chat Session Key Agreement")
        
        # Generate new DH keypair for chat session
        chat_dh_private, chat_dh_public = self.crypto.generate_dh_keypair()
        
        # Send DH parameters
        dh_msg = ProtocolMessage.dh_client(DH_G, DH_P, chat_dh_public)
        self.socket.send(ProtocolMessage.encode(dh_msg))
        
        # Receive server DH response
        data = self.socket.recv(4096)
        dh_response = ProtocolMessage.decode(data)
        
        if not MessageValidator.validate_dh_server(dh_response):
            print("[!] Invalid DH response")
            return False
        
        # Compute shared secret and derive chat session key
        server_chat_public = dh_response['B']
        chat_shared_secret = self.crypto.compute_dh_shared_secret(chat_dh_private, server_chat_public)
        self.state.session_key = self.crypto.derive_aes_key(chat_shared_secret)
        self.state.state = ProtocolState.KEY_AGREED
        
        print("[+] Chat session key established")
        return True
    
    def chat(self, username):
        """Phase 5: Encrypted chat session"""
        print("\n[*] Phase 5: Secure Chat Session")
        print("[*] Type your messages (type '/quit' to exit)")
        print("=" * 50)
        
        self.state.state = ProtocolState.CHATTING
        peer_fingerprint = self.crypto.get_cert_fingerprint(self.state.peer_cert)
        
        try:
            while True:
                # Send message
                message = input("\nYou: ")
                
                if message.lower() == '/quit':
                    quit_msg = {"type": "quit"}
                    self.socket.send(ProtocolMessage.encode(quit_msg))
                    break
                
                # Encrypt message
                ciphertext = self.crypto.aes_encrypt(message, self.state.session_key)
                
                # Create signature
                seqno = self.state.increment_send_seqno()
                timestamp = int(time.time() * 1000)
                digest_data = f"{seqno}{timestamp}{ciphertext}"
                signature = self.crypto.rsa_sign(self.client_key, digest_data)
                
                # Send encrypted and signed message
                msg = ProtocolMessage.chat_message(seqno, timestamp, ciphertext, signature)
                self.socket.send(ProtocolMessage.encode(msg))
                
                # Add to transcript
                client_fingerprint = self.crypto.get_cert_fingerprint(self.client_cert)
                self.state.add_to_transcript(seqno, timestamp, ciphertext, signature, client_fingerprint)
                
                # Receive response
                data = self.socket.recv(8192)
                if not data:
                    break
                
                response = ProtocolMessage.decode(data)
                
                if response['type'] == 'error':
                    print(f"[!] Error: {response['error']} - {response['message']}")
                    continue
                
                if response['type'] == 'msg':
                    # Validate message
                    if not MessageValidator.validate_chat_message(response):
                        print("[!] Invalid message format")
                        continue
                    
                    # Check sequence number
                    if not self.state.verify_receive_seqno(response['seqno']):
                        print(f"[!] REPLAY: Invalid sequence number")
                        continue
                    
                    # Verify signature
                    digest_data = f"{response['seqno']}{response['ts']}{response['ct']}"
                    if not self.crypto.rsa_verify(self.state.peer_public_key, digest_data, response['sig']):
                        print(f"[!] SIG_FAIL: Invalid signature")
                        continue
                    
                    # Decrypt message
                    plaintext = self.crypto.aes_decrypt(response['ct'], self.state.session_key)
                    print(f"Server: {plaintext.decode('utf-8')}")
                    
                    # Add to transcript
                    self.state.add_to_transcript(
                        response['seqno'],
                        response['ts'],
                        response['ct'],
                        response['sig'],
                        peer_fingerprint
                    )
        
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
        
        # Generate session receipt
        self.generate_receipt(username)
    
    def generate_receipt(self, username):
        """Phase 6: Generate non-repudiation receipt"""
        print("\n[*] Phase 6: Generating Session Receipt")
        
        if not self.state.transcript:
            print("[!] No messages in transcript")
            return
        
        # Compute transcript hash
        transcript_hash = self.state.get_transcript_hash(self.crypto)
        
        # Sign transcript hash
        receipt_sig = self.crypto.rsa_sign(self.client_key, transcript_hash)
        
        # Create receipt
        receipt = ProtocolMessage.session_receipt(
            "client",
            1,
            self.state.seqno_sent,
            transcript_hash,
            receipt_sig
        )
        
        # Save transcript and receipt
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        transcript_file = f"transcripts/client_{username}_{timestamp_str}.txt"
        
        peer_fingerprint = self.crypto.get_cert_fingerprint(self.state.peer_cert)
        
        with open(transcript_file, 'w') as f:
            f.write("=== Session Transcript ===\n")
            f.write(f"User: {username}\n")
            f.write(f"Server Certificate Fingerprint: {peer_fingerprint}\n")
            f.write(f"Session Time: {timestamp_str}\n\n")
            for entry in self.state.transcript:
                f.write(entry + "\n")
            f.write(f"\n=== Session Receipt ===\n")
            f.write(json.dumps(receipt, indent=2))
        
        print(f"[+] Transcript saved: {transcript_file}")
        print(f"[+] Receipt hash: {transcript_hash[:16]}...")
    
    def run(self):
        """Main client flow"""
        try:
            # Connect to server
            self.connect()
            
            # Phase 1: Certificate exchange
            if not self.exchange_certificates():
                return
            
            # Phase 2: Temporary DH for auth
            temp_aes_key = self.temporary_dh_exchange()
            if not temp_aes_key:
                return
            
            # Phase 3: Register or Login
            print("\n[*] Phase 3: Authentication")
            choice = input("Choose: (1) Register  (2) Login: ")
            
            if choice == '1':
                success, username = self.register(temp_aes_key)
            elif choice == '2':
                success, username = self.login(temp_aes_key)
            else:
                print("[!] Invalid choice")
                return
            
            if not success:
                return
            
            self.state.state = ProtocolState.AUTHENTICATED
            
            # Phase 4: Chat session key agreement
            if not self.chat_session_dh():
                return
            
            # Phase 5: Chat
            self.chat(username)
            
        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            if self.socket:
                self.socket.close()
                print("\n[*] Disconnected")


if __name__ == '__main__':
    print("=" * 60)
    print("          SECURE CHAT CLIENT")
    print("=" * 60)
    
    client = SecureChatClient()
    client.run()
