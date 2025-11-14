# Secure Chat System

A cryptographically secure console-based chat application implementing end-to-end encryption with mutual authentication, demonstrating **Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**.

## 🔐 Features

- **PKI & X.509 Certificates**: Self-built Certificate Authority with mutual authentication
- **Secure Registration**: Salted SHA-256 password hashing, no plaintext credentials
- **Diffie-Hellman Key Exchange**: Session key establishment without transmission
- **AES-128 Encryption**: Block cipher with PKCS#7 padding for confidentiality
- **RSA Digital Signatures**: Per-message integrity and authenticity verification
- **Replay Protection**: Sequence numbers and timestamp validation
- **Non-Repudiation**: Signed session transcripts with verifiable receipts

## 📋 Prerequisites

- Python 3.8+
- MySQL 5.7+ or MariaDB
- pip (Python package manager)

## 🚀 Setup Instructions

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/securechat-skeleton.git
cd securechat-skeleton
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Setup MySQL Database

```bash
# Login to MySQL
mysql -u root -p

# Create database and import schema
CREATE DATABASE securechat;
USE securechat;
SOURCE schema.sql;
```

### 4. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your database credentials
nano .env
```

Update the following in `.env`:
```
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=your_mysql_password
DB_NAME=securechat
```

### 5. Generate Certificates

```bash
# Create Certificate Authority
python scripts/gen_ca.py

# Generate server certificate
python scripts/gen_cert.py server

# Generate client certificate
python scripts/gen_cert.py client
```

**Important**: The `certs/` directory is gitignored. Never commit certificates or private keys!

## 🎯 Running the Application

### Start Server

```bash
python src/server.py
```

Expected output:
```
[*] Server initialized on localhost:5555
[*] Server certificate loaded: CN=securechat.server
[+] Connected to database
[✓] Server listening on localhost:5555
[*] Waiting for clients...
```

### Start Client (in new terminal)

```bash
python src/client.py
```

Follow the prompts:
1. Choose Register (1) or Login (2)
2. Enter credentials
3. Start chatting
4. Type `/quit` to exit

## 📊 Protocol Flow

### Phase 1: Control Plane (Certificate Exchange)
- Client sends certificate + nonce
- Server verifies client certificate against CA
- Server sends certificate + nonce
- Client verifies server certificate

### Phase 2: Temporary DH (For Auth)
- Diffie-Hellman key exchange
- Derive temporary AES key for credential encryption

### Phase 3: Authentication
- Register: Email, username, salted password hash stored in MySQL
- Login: Verify salted hash against database

### Phase 4: Session Key Agreement
- New DH exchange for chat session
- Derive AES-128 session key: `K = Trunc16(SHA256(Ks))`

### Phase 5: Data Plane (Encrypted Chat)
- Messages encrypted with AES-128
- Each message signed: `sig = RSA_SIGN(SHA256(seqno||ts||ct))`
- Sequence numbers prevent replay attacks
- Timestamps reject stale messages

### Phase 6: Teardown (Non-Repudiation)
- Generate transcript hash: `SHA256(all messages)`
- Sign transcript hash with RSA private key
- Save SessionReceipt for offline verification

## 🔬 Testing

### Wireshark Capture

```bash
# Start Wireshark and capture on loopback interface
# Apply filter:
tcp.port == 5555 && json

# Verify:
# - Certificates exchanged in plaintext
# - All messages after DH are encrypted (base64 ciphertext)
# - No plaintext passwords visible
```

### Invalid Certificate Test

```bash
# Replace client cert with self-signed certificate
openssl req -x509 -newkey rsa:2048 -nodes -keyout fake_key.pem -out fake_cert.pem -days 365

# Modify client.py to use fake certificate
# Expected: Server rejects with "BAD_CERT" error
```

### Tampering Test

```bash
# In client.py, modify ciphertext before sending:
# msg['ct'] = msg['ct'][:-5] + 'XXXXX'  # Flip bits

# Expected: Server verifies signature fails → "SIG_FAIL" error
```

### Replay Attack Test

```bash
# Capture a message packet
# Resend the same packet again
# Expected: Server detects duplicate seqno → "REPLAY" error
```

### Non-Repudiation Verification

```bash
# After chat session, check transcripts/ directory
# Verify each message signature:
python scripts/verify_transcript.py transcripts/client_username_20251102_143022.txt

# Expected: All signatures valid, receipt signature valid
```

## 📁 File Structure

```
securechat/
├── certs/                      # Certificates (gitignored)
│   ├── ca_key.pem
│   ├── ca_cert.pem
│   ├── server_key.pem
│   ├── server_cert.pem
│   ├── client_key.pem
│   └── client_cert.pem
├── scripts/
│   ├── gen_ca.py              # Generate root CA
│   └── gen_cert.py            # Generate certificates
├── src/
│   ├── crypto_utils.py        # Crypto primitives
│   ├── protocol.py            # Protocol handlers
│   ├── server.py              # Server implementation
│   └── client.py              # Client implementation
├── transcripts/               # Session transcripts (gitignored)
├── .env                       # Environment config (gitignored)
├── .env.example               # Environment template
├── .gitignore                 # Git exclusions
├── requirements.txt           # Python dependencies
├── schema.sql                 # Database schema
└── README.md                  # This file
```

## 🔍 Message Formats

### Hello Message
```json
{
  "type": "hello",
  "client_cert": "-----BEGIN CERTIFICATE-----...",
  "nonce": "base64_encoded_nonce"
}
```

### Chat Message
```json
{
  "type": "msg",
  "seqno": 1,
  "ts": 1698765432000,
  "ct": "base64_encrypted_message",
  "sig": "base64_rsa_signature"
}
```

### Session Receipt
```json
{
  "type": "receipt",
  "peer": "client",
  "first_seq": 1,
  "last_seq": 10,
  "transcript_sha256": "abc123...",
  "sig": "base64_signature"
}
```

## 🛡️ Security Features

| Feature | Implementation |
|---------|---------------|
| **Confidentiality** | AES-128 encryption with unique session keys |
| **Integrity** | SHA-256 hashing of all message components |
| **Authenticity** | RSA signatures + X.509 certificate validation |
| **Non-Repudiation** | Signed transcripts stored permanently |
| **Replay Protection** | Strictly increasing sequence numbers |
| **Forward Secrecy** | New DH exchange per session |
| **Password Security** | Random 16-byte salts + SHA-256 hashing |

## 📝 Sample Input/Output

### Registration
```
Choose: (1) Register  (2) Login: 1
Email: alice@example.com
Username: alice
Password: SecurePass123!

[+] Registration successful
```

### Chat Session
```
You: Hello, this is a secure message!
Server: Message received and encrypted!

You: Testing integrity and signatures
Server: All signatures verified ✓

You: /quit
[*] Phase 6: Generating Session Receipt
[+] Transcript saved: transcripts/client_alice_20251102_143530.txt
[+] Receipt hash: d4f2b8e1c9a7...
```

## 🐛 Troubleshooting

### Database Connection Error
```bash
# Ensure MySQL is running
sudo systemctl start mysql

# Check credentials in .env
mysql -u root -p
```

### Certificate Errors
```bash
# Regenerate certificates
rm -rf certs/
python scripts/gen_ca.py
python scripts/gen_cert.py server
python scripts/gen_cert.py client
```

### Port Already in Use
```bash
# Find process using port 5555
lsof -i :5555

# Kill process or change port in code
```

## 📚 References

- [RFC 3526](https://www.rfc-editor.org/rfc/rfc3526) - Diffie-Hellman Parameters
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) - X.509 Certificates
- [PKCS#7 Padding](https://www.rfc-editor.org/rfc/rfc5652)
- [SEED Labs PKI](https://seedsecuritylabs.org/Labs_20.04/Crypto/Crypto_PKI/)

## 👥 Contributors

- **Your Name** - Implementation
- **FAST NUCES** - Assignment Framework

## 📄 License

This is an academic project for Information Security coursework at FAST-NUCES.

## 🔗 Repository

GitHub: [https://github.com/yourusername/securechat-skeleton](https://github.com/yourusername/securechat-skeleton)

---

**Note**: This implementation is for educational purposes. For production systems, use established libraries like TLS/SSL.
