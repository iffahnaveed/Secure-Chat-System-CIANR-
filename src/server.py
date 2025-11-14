"""
Secure Chat Server
Handles client connections, authentication, and encrypted messaging
"""

import socket
import json
import time
import os
import base64
from datetime import datetime
from dotenv import load_dotenv
import mysql.connector
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from crypto_utils import CryptoUtils, DH_P, DH_G
from protocol import ProtocolMessage, ProtocolState, MessageValidator

# Load environment variables
load_dotenv()


class SecureChatServer:
    """Secure chat server implementation"""
    
    def __init__(self, host='localhost', port=5555):
        self.host = host
        self.port = port
        self.crypto = CryptoUtils()
        
        # Load server certificate and private key
        self.server_cert = self.crypto.load_certificate('certs/server_cert.pem')
        self.server_key = self.crypto.load_private_key('certs/server_key.pem')
        
        # Load CA certificate for verification
        self.ca_cert = self.crypto.load_certificate('certs/ca_cert.pem')
        
        # Get server cert as PEM string
        self.server_cert_pem = self.server_cert.public_bytes(
            serialization.Encoding.PEM
        ).decode('utf-8')
        
        # Database connection
        self.db_conn = None
        self.connect_database()
        
        # Create transcripts directory
        os.makedirs('transcripts', exist_ok=True)
        
        print(f"[*] Server initialized on {self.host}:{self.port}")
        print(f"[*] Server certificate loaded: CN={self.server_cert.subject.rfc4514_string()}")
    
    def connect_database(self):
        """Connect to MySQL database"""
        try:
            self.db_conn = mysql.connector.connect(
                host=os.getenv('DB_HOST', 'localhost'),
                user=os.getenv('DB_USER', 'root'),
                password=os.getenv('DB_PASSWORD', ''),
                database=os.getenv('DB_NAME', 'securechat')
            )
            print("[+] Connected to database")
        except Exception as e:
            print(f"[!] Database connection failed: {e}")
            raise
    
    def register_user(self, email, username, salt, pwd_hash):
        """Register new user in database"""
        try:
            cursor = self.db_conn.cursor()
            
            # Check if user already exists
            cursor.execute("SELECT * FROM users WHERE email = %s OR username = %s", 
                          (email, username))
            if cursor.fetchone():
                cursor.close()
                return False, "User already exists"
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
            self.db_conn.commit()
            cursor.close()
            
            print(f"[+] User registered: {username} ({email})")
            return True, "Registration successful"
            
        except Exception as e:
            print(f"[!] Registration error: {e}")
            return False, str(e)
    
    def authenticate_user(self, email, pwd_hash):
        """Authenticate user login"""
        try:
            cursor = self.db_conn.cursor()
            cursor.execute("SELECT salt, pwd_hash, username FROM users WHERE email = %s", (email,))
            result = cursor.fetchone()
            cursor.close()
            
            if not result:
                return False, None, "User not found"
            
            stored_salt, stored_hash, username = result
            
            # Recompute hash with stored salt
            recomputed_hash = self.crypto.sha256_hash(stored_salt + base64.b64decode(pwd_hash))
            
            # Constant-time comparison
            if self.crypto.constant_time_compare(recomputed_hash, stored_hash):
                # Update last login
                cursor = self.db_conn.cursor()
                cursor.execute("UPDATE users SET last_login = NOW() WHERE email = %s", (email,))
                self.db_conn.commit()
                cursor.close()
                
                print(f"[+] User authenticated: {username} ({email})")
                return True, username, "Login successful"
            else:
                return False, None, "Invalid credentials"
                
        except Exception as e:
            print(f"[!] Authentication error: {e}")
            return False, None, str(e)
    
    def handle_client(self, client_socket, addr):
        """Handle individual client connection"""
        print(f"\n[*] New connection from {addr}")
        state = ProtocolState()
        temp_aes_key = None
        username = None
        
        try:
            # Phase 1: Certificate Exchange (Control Plane)
            print(f"[*] Phase 1: Certificate Exchange")
            
            # Receive client hello
            data = client_socket.recv(8192)
            hello_msg = ProtocolMessage.decode(data)
            
            if not MessageValidator.validate_hello(hello_msg):
                raise Exception("Invalid hello message")
            
            # Load and verify client certificate
            client_cert_pem = hello_msg['client_cert']
            client_cert = x509.load_pem_x509_certificate(
                client_cert_pem.encode('utf-8'),
                default_backend()
            )
            
            is_valid, error_msg = self.crypto.verify_certificate(client_cert, self.ca_cert)
            if not is_valid:
                print(f"[!] BAD_CERT: {error_msg}")
                error_response = ProtocolMessage.error("BAD_CERT", error_msg)
                client_socket.send(ProtocolMessage.encode(error_response))
                return
            
            print(f"[+] Client certificate verified: CN={client_cert.subject.rfc4514_string()}")
            state.peer_cert = client_cert
            state.peer_public_key = client_cert.public_key()
            
            # Send server hello
            server_nonce = self.crypto.generate_nonce()
            server_hello = ProtocolMessage.server_hello(self.server_cert_pem, server_nonce)
            client_socket.send(ProtocolMessage.encode(server_hello))
            state.state = ProtocolState.CERT_EXCHANGED
            
            # Phase 2: Temporary DH for registration/login encryption
            print(f"[*] Phase 2: Temporary DH Exchange")
            
            # Receive client DH params
            data = client_socket.recv(4096)
            dh_msg = ProtocolMessage.decode(data)
            
            if not MessageValidator.validate_dh_client(dh_msg):
                raise Exception("Invalid DH message")
            
            # Generate server DH keypair
            server_dh_private, server_dh_public = self.crypto.generate_dh_keypair()
            
            # Send server DH public key
            dh_response = ProtocolMessage.dh_server(server_dh_public)
            client_socket.send(ProtocolMessage.encode(dh_response))
            
            # Compute shared secret and derive temporary AES key
            client_dh_public = dh_msg['A']
            shared_secret = self.crypto.compute_dh_shared_secret(server_dh_private, client_dh_public)
            temp_aes_key = self.crypto.derive_aes_key(shared_secret)
            print(f"[+] Temporary session key established")
            
            # Phase 3: Registration or Login
            print(f"[*] Phase 3: Authentication")
            
            # Receive encrypted credentials
            data = client_socket.recv(4096)
            encrypted_payload = ProtocolMessage.decode(data)
            
            # Decrypt credentials
            decrypted = self.crypto.aes_decrypt(encrypted_payload['payload'], temp_aes_key)
            cred_msg = json.loads(decrypted.decode('utf-8'))
            
            if cred_msg['type'] == 'register':
                # Handle registration
                salt = base64.b64decode(cred_msg['salt'])
                pwd_hash = self.crypto.sha256_hash(salt + base64.b64decode(cred_msg['pwd']))
                
                success, message = self.register_user(
                    cred_msg['email'],
                    cred_msg['username'],
                    salt,
                    pwd_hash
                )
                
                if success:
                    username = cred_msg['username']
                    response = ProtocolMessage.ack("success", message)
                else:
                    response = ProtocolMessage.error("REG_FAILED", message)
                    encrypted_response = self.crypto.aes_encrypt(
                        ProtocolMessage.encode(response),
                        temp_aes_key
                    )
                    client_socket.send(ProtocolMessage.encode({"payload": encrypted_response}))
                    return
                
            elif cred_msg['type'] == 'login':
                # Handle login
                success, uname, message = self.authenticate_user(
                    cred_msg['email'],
                    cred_msg['pwd']
                )
                
                if success:
                    username = uname
                    response = ProtocolMessage.ack("success", message)
                else:
                    response = ProtocolMessage.error("AUTH_FAILED", message)
                    encrypted_response = self.crypto.aes_encrypt(
                        ProtocolMessage.encode(response),
                        temp_aes_key
                    )
                    client_socket.send(ProtocolMessage.encode({"payload": encrypted_response}))
                    return
            else:
                raise Exception("Invalid credential message type")
            
            # Send encrypted response
            encrypted_response = self.crypto.aes_encrypt(
                ProtocolMessage.encode(response),
                temp_aes_key
            )
            client_socket.send(ProtocolMessage.encode({"payload": encrypted_response}))
            state.state = ProtocolState.AUTHENTICATED
            
            # Phase 4: Session Key Agreement (Chat DH)
            print(f"[*] Phase 4: Chat Session Key Agreement")
            
            # Receive client DH for chat session
            data = client_socket.recv(4096)
            chat_dh_msg = ProtocolMessage.decode(data)
            
            # Generate new DH keypair for chat session
            chat_dh_private, chat_dh_public = self.crypto.generate_dh_keypair()
            
            # Send server DH public key
            chat_dh_response = ProtocolMessage.dh_server(chat_dh_public)
            client_socket.send(ProtocolMessage.encode(chat_dh_response))
            
            # Compute shared secret and derive chat session key
            client_chat_public = chat_dh_msg['A']
            chat_shared_secret = self.crypto.compute_dh_shared_secret(chat_dh_private, client_chat_public)
            state.session_key = self.crypto.derive_aes_key(chat_shared_secret)
            state.state = ProtocolState.KEY_AGREED
            print(f"[+] Chat session key established for {username}")
            
            # Phase 5: Encrypted Chat (Data Plane)
            print(f"[*] Phase 5: Secure Chat Session Started")
            state.state = ProtocolState.CHATTING
            
            peer_fingerprint = self.crypto.get_cert_fingerprint(client_cert)
            
            while True:
                data = client_socket.recv(8192)
                if not data:
                    break
                
                msg = ProtocolMessage.decode(data)
                
                if msg['type'] == 'msg':
                    # Validate message
                    if not MessageValidator.validate_chat_message(msg):
                        print("[!] Invalid message format")
                        continue
                    
                    # Check sequence number (replay protection)
                    if not state.verify_receive_seqno(msg['seqno']):
                        print(f"[!] REPLAY: Invalid sequence number {msg['seqno']}")
                        error_msg = ProtocolMessage.error("REPLAY", "Replay detected")
                        client_socket.send(ProtocolMessage.encode(error_msg))
                        continue
                    
                    # Validate timestamp
                    if not MessageValidator.validate_timestamp(msg['ts']):
                        print(f"[!] STALE: Message timestamp too old")
                        continue
                    
                    # Verify signature
                    digest_data = f"{msg['seqno']}{msg['ts']}{msg['ct']}"
                    if not self.crypto.rsa_verify(state.peer_public_key, digest_data, msg['sig']):
                        print(f"[!] SIG_FAIL: Invalid signature")
                        error_msg = ProtocolMessage.error("SIG_FAIL", "Signature verification failed")
                        client_socket.send(ProtocolMessage.encode(error_msg))
                        continue
                    
                    # Decrypt message
                    plaintext = self.crypto.aes_decrypt(msg['ct'], state.session_key)
                    print(f"\n[{username}]: {plaintext.decode('utf-8')}")
                    
                    # Add to transcript
                    state.add_to_transcript(
                        msg['seqno'],
                        msg['ts'],
                        msg['ct'],
                        msg['sig'],
                        peer_fingerprint
                    )
                    
                    # Echo back or send server message
                    response_text = input("[Server]: ")
                    if response_text.lower() == '/quit':
                        break
                    
                    # Encrypt and sign response
                    response_ct = self.crypto.aes_encrypt(response_text, state.session_key)
                    seqno = state.increment_send_seqno()
                    timestamp = int(time.time() * 1000)
                    
                    digest_data = f"{seqno}{timestamp}{response_ct}"
                    signature = self.crypto.rsa_sign(self.server_key, digest_data)
                    
                    response_msg = ProtocolMessage.chat_message(seqno, timestamp, response_ct, signature)
                    client_socket.send(ProtocolMessage.encode(response_msg))
                    
                    # Add to transcript
                    server_fingerprint = self.crypto.get_cert_fingerprint(self.server_cert)
                    state.add_to_transcript(seqno, timestamp, response_ct, signature, server_fingerprint)
                
                elif msg['type'] == 'quit':
                    print(f"[*] Client {username} disconnecting")
                    break
            
            # Phase 6: Session Teardown - Generate Receipt
            print(f"[*] Phase 6: Generating Session Receipt")
            
            if state.transcript:
                transcript_hash = state.get_transcript_hash(self.crypto)
                receipt_sig = self.crypto.rsa_sign(self.server_key, transcript_hash)
                
                receipt = ProtocolMessage.session_receipt(
                    "server",
                    1,
                    state.seqno_sent,
                    transcript_hash,
                    receipt_sig
                )
                
                # Save transcript and receipt
                timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
                transcript_file = f"transcripts/server_{username}_{timestamp_str}.txt"
                
                with open(transcript_file, 'w') as f:
                    f.write("=== Session Transcript ===\n")
                    f.write(f"Peer: {username}\n")
                    f.write(f"Peer Certificate Fingerprint: {peer_fingerprint}\n")
                    f.write(f"Session Start: {timestamp_str}\n\n")
                    for entry in state.transcript:
                        f.write(entry + "\n")
                    f.write(f"\n=== Session Receipt ===\n")
                    f.write(json.dumps(receipt, indent=2))
                
                print(f"[+] Transcript saved: {transcript_file}")
                print(f"[+] Receipt hash: {transcript_hash[:16]}...")
            
        except Exception as e:
            print(f"[!] Error handling client: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            client_socket.close()
            print(f"[*] Connection closed: {addr}")
    
    def start(self):
        """Start server and listen for connections"""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"\n[✓] Server listening on {self.host}:{self.port}")
        print(f"[*] Waiting for clients...\n")
        
        try:
            while True:
                client_socket, addr = server_socket.accept()
                self.handle_client(client_socket, addr)
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            server_socket.close()
            if self.db_conn:
                self.db_conn.close()


if __name__ == '__main__':
    server = SecureChatServer()
    server.start()
