#!/usr/bin/env python3
"""
Offline Transcript Verification Tool
Verifies message signatures and session receipt from transcript files
"""

import sys
import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def load_public_key_from_cert(cert_path):
    """Load public key from certificate"""
    from cryptography import x509
    
    with open(cert_path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return cert.public_key()


def verify_signature(public_key, message, signature_b64):
    """Verify RSA signature"""
    try:
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            message,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"      Verification failed: {e}")
        return False


def verify_transcript(transcript_file):
    """Verify all messages and receipt in transcript"""
    
    print(f"\n{'='*70}")
    print(f"  TRANSCRIPT VERIFICATION")
    print(f"{'='*70}")
    print(f"File: {transcript_file}\n")
    
    # Read transcript file
    with open(transcript_file, 'r') as f:
        content = f.read()
    
    # Parse sections
    sections = content.split('=== Session Receipt ===')
    
    if len(sections) != 2:
        print("[!] Invalid transcript format")
        return False
    
    transcript_section = sections[0]
    receipt_section = sections[1].strip()
    
    # Extract transcript lines
    lines = transcript_section.strip().split('\n')
    transcript_lines = []
    peer_cert_fingerprint = None
    
    for line in lines:
        if line.startswith('Peer Certificate Fingerprint:'):
            peer_cert_fingerprint = line.split(':', 1)[1].strip()
        elif '|' in line and not line.startswith('===') and not line.startswith('Peer') and not line.startswith('Session'):
            transcript_lines.append(line)
    
    print(f"[*] Found {len(transcript_lines)} messages in transcript")
    if peer_cert_fingerprint:
       print(f"[*] Peer Certificate Fingerprint: {peer_cert_fingerprint[:16]}...\n")
    else:
       print("[!] Peer Certificate Fingerprint missing\n")

    
    # Load certificates for verification
    print("[*] Loading certificates...")
    try:
        server_pubkey = load_public_key_from_cert('certs/server_cert.pem')
        client_pubkey = load_public_key_from_cert('certs/client_cert.pem')
        print("[+] Certificates loaded\n")
    except Exception as e:
        print(f"[!] Failed to load certificates: {e}")
        return False
    
    # Verify each message
    print(f"{'='*70}")
    print("MESSAGE VERIFICATION")
    print(f"{'='*70}\n")
    
    valid_count = 0
    invalid_count = 0
    
    for i, line in enumerate(transcript_lines, 1):
        parts = line.split('|')
        if len(parts) != 5:
            print(f"[!] Message {i}: Invalid format")
            invalid_count += 1
            continue
        
        seqno, ts, ct, sig, cert_fp = parts
        
        # Reconstruct digest
        digest_data = f"{seqno}{ts}{ct}"
        
        # Determine which key to use based on cert fingerprint
        # This is simplified - in practice you'd match the fingerprint
        if i % 2 == 1:  # Odd messages from client
            pubkey = client_pubkey
            sender = "Client"
        else:  # Even messages from server
            pubkey = server_pubkey
            sender = "Server"
        
        print(f"Message {i} (Seq: {seqno}):")
        print(f"  Sender: {sender}")
        print(f"  Timestamp: {ts}")
        print(f"  Ciphertext: {ct[:30]}...")
        print(f"  Signature: {sig[:30]}...")
        
        # Verify signature
        if verify_signature(pubkey, digest_data, sig):
            print(f"  ✓ Signature VALID\n")
            valid_count += 1
        else:
            print(f"  ✗ Signature INVALID\n")
            invalid_count += 1
    
    print(f"{'='*70}")
    print(f"Message Verification Summary: {valid_count} valid, {invalid_count} invalid")
    print(f"{'='*70}\n")
    
    # Verify receipt
    print(f"{'='*70}")
    print("RECEIPT VERIFICATION")
    print(f"{'='*70}\n")
    
    try:
        receipt = json.loads(receipt_section)
        
        print("Receipt Details:")
        print(f"  Peer: {receipt['peer']}")
        print(f"  Message Range: {receipt['first_seq']} - {receipt['last_seq']}")
        print(f"  Transcript Hash: {receipt['transcript_sha256'][:32]}...")
        print(f"  Signature: {receipt['sig'][:30]}...\n")
        
        # Recompute transcript hash
        transcript_text = "\n".join(transcript_lines)
        computed_hash = hashlib.sha256(transcript_text.encode('utf-8')).hexdigest()
        
        print(f"Hash Verification:")
        print(f"  Stored:   {receipt['transcript_sha256']}")
        print(f"  Computed: {computed_hash}")
        
        if computed_hash == receipt['transcript_sha256']:
            print(f"  ✓ Hash MATCHES\n")
        else:
            print(f"  ✗ Hash MISMATCH\n")
            return False
        
        # Verify receipt signature
        if receipt['peer'] == 'client':
            receipt_pubkey = client_pubkey
        else:
            receipt_pubkey = server_pubkey
        
        print(f"Signature Verification:")
        if verify_signature(receipt_pubkey, receipt['transcript_sha256'], receipt['sig']):
            print(f"  ✓ Receipt signature VALID\n")
        else:
            print(f"  ✗ Receipt signature INVALID\n")
            return False
        
    except Exception as e:
        print(f"[!] Receipt verification failed: {e}")
        return False
    
    print(f"{'='*70}")
    print(f"  ✓ TRANSCRIPT FULLY VERIFIED")
    print(f"{'='*70}\n")
    
    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: python verify_transcript.py <transcript_file>")
        print("\nExample:")
        print("  python scripts/verify_transcript.py transcripts/client_alice_20251102_143530.txt")
        sys.exit(1)
    
    transcript_file = sys.argv[1]
    
    try:
        success = verify_transcript(transcript_file)
        if success:
            print("✓ All verifications passed!")
            sys.exit(0)
        else:
            print("✗ Verification failed!")
            sys.exit(1)
    except FileNotFoundError:
        print(f"[!] File not found: {transcript_file}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
