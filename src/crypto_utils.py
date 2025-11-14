"""
Cryptographic Utilities
Implements AES-128, RSA, Diffie-Hellman, and SHA-256 operations
"""

import os
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography import x509


# Diffie-Hellman parameters (RFC 3526 - 2048-bit MODP Group)
DH_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
DH_G = 2


class CryptoUtils:
    """Cryptographic operations handler"""
    
    @staticmethod
    def generate_dh_keypair():
        """
        Generate Diffie-Hellman keypair
        Returns: (private_key, public_key)
        """
        # Generate random private key (256 bits)
        private_key = int.from_bytes(os.urandom(32), byteorder='big') % (DH_P - 2) + 1
        # Compute public key: g^a mod p
        public_key = pow(DH_G, private_key, DH_P)
        return private_key, public_key
    
    @staticmethod
    def compute_dh_shared_secret(private_key, peer_public_key):
        """
        Compute Diffie-Hellman shared secret
        Returns: shared_secret (integer)
        """
        return pow(peer_public_key, private_key, DH_P)
    
    @staticmethod
    def derive_aes_key(shared_secret):
        """
        Derive AES-128 key from DH shared secret
        K = Trunc16(SHA256(big-endian(Ks)))
        Returns: 16-byte AES key
        """
        # Convert shared secret to big-endian bytes
        # Calculate byte length needed
        byte_length = (shared_secret.bit_length() + 7) // 8
        shared_secret_bytes = shared_secret.to_bytes(byte_length, byteorder='big')
        
        # Hash and truncate to 16 bytes
        hash_digest = hashlib.sha256(shared_secret_bytes).digest()
        aes_key = hash_digest[:16]  # First 16 bytes for AES-128
        return aes_key
    
    @staticmethod
    def aes_encrypt(plaintext, key):
        """
        Encrypt plaintext using AES-128 with PKCS#7 padding
        Args:
            plaintext: bytes or str
            key: 16-byte AES key
        Returns: base64-encoded ciphertext
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Apply PKCS#7 padding
        block_size = 16
        padding_length = block_size - (len(plaintext) % block_size)
        padded_plaintext = plaintext + bytes([padding_length] * padding_length)
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Prepend IV to ciphertext and encode
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    @staticmethod
    def aes_decrypt(ciphertext_b64, key):
        """
        Decrypt AES-128 ciphertext and remove PKCS#7 padding
        Args:
            ciphertext_b64: base64-encoded ciphertext (with IV prepended)
            key: 16-byte AES key
        Returns: plaintext bytes
        """
        # Decode base64
        data = base64.b64decode(ciphertext_b64)
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        # Decrypt
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove PKCS#7 padding
        padding_length = padded_plaintext[-1]
        plaintext = padded_plaintext[:-padding_length]
        
        return plaintext
    
    @staticmethod
    def sha256_hash(data):
        """
        Compute SHA-256 hash
        Args:
            data: bytes or str
        Returns: hex digest string
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def sha256_hash_bytes(data):
        """
        Compute SHA-256 hash
        Args:
            data: bytes or str
        Returns: bytes digest
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        return hashlib.sha256(data).digest()
    
    @staticmethod
    def rsa_sign(private_key, message):
        """
        Sign message with RSA private key
        Args:
            private_key: RSA private key object
            message: bytes or str to sign
        Returns: base64-encoded signature
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = private_key.sign(
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def rsa_verify(public_key, message, signature_b64):
        """
        Verify RSA signature
        Args:
            public_key: RSA public key object
            message: bytes or str that was signed
            signature_b64: base64-encoded signature
        Returns: True if valid, False otherwise
        """
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        try:
            signature = base64.b64decode(signature_b64)
            public_key.verify(
                signature,
                message,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def load_certificate(cert_path):
        """Load X.509 certificate from PEM file"""
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert
    
    @staticmethod
    def load_private_key(key_path):
        """Load RSA private key from PEM file"""
        with open(key_path, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return private_key
    
    @staticmethod
    def verify_certificate(cert, ca_cert):
        """
        Verify certificate against CA certificate
        Checks:
        - Signature validity
        - Expiry dates
        - Trust chain
        Returns: (is_valid, error_message)
        """
        try:
            # Check expiry
            now = datetime.utcnow()
            if now < cert.not_valid_before:
                return False, "Certificate not yet valid"
            if now > cert.not_valid_after:
                return False, "Certificate has expired"
            
            # Verify signature
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm
            )
            
            # Check if signed by CA
            if cert.issuer != ca_cert.subject:
                return False, "Certificate not signed by trusted CA"
            
            return True, "Valid"
            
        except Exception as e:
            return False, f"Verification failed: {str(e)}"
    
    @staticmethod
    def get_cert_fingerprint(cert):
        """Get SHA-256 fingerprint of certificate"""
        cert_bytes = cert.public_bytes(serialization.Encoding.DER)
        return hashlib.sha256(cert_bytes).hexdigest()
    
    @staticmethod
    def generate_nonce():
        """Generate random nonce (16 bytes)"""
        return base64.b64encode(os.urandom(16)).decode('utf-8')
    
    @staticmethod
    def generate_salt():
        """Generate random salt (16 bytes)"""
        return os.urandom(16)
    
    @staticmethod
    def constant_time_compare(a, b):
        """
        Constant-time string comparison to prevent timing attacks
        """
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= ord(x) ^ ord(y) if isinstance(x, str) else x ^ y
        return result == 0
