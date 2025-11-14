#!/usr/bin/env python3
"""
Generate Root Certificate Authority (CA)
Creates a self-signed root CA certificate and private key
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_ca():
    """Generate root CA certificate and private key"""
    
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    print("[*] Generating Root CA...")
    
    # Generate RSA private key for CA
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create CA certificate subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Khyber Pakhtunkhwa"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Peshawar"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"Information Security"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"SecureChat Root CA"),
    ])
    
    # Build the CA certificate
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    # Write CA private key to file
    with open('certs/ca_key.pem', 'wb') as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print("[+] CA private key saved to certs/ca_key.pem")
    
    # Write CA certificate to file
    with open('certs/ca_cert.pem', 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    print("[+] CA certificate saved to certs/ca_cert.pem")
    
    # Display certificate info
    print("\n[*] Root CA Certificate Details:")
    print(f"    Subject: {ca_cert.subject.rfc4514_string()}")
    print(f"    Serial Number: {ca_cert.serial_number}")
    print(f"    Valid From: {ca_cert.not_valid_before}")
    print(f"    Valid Until: {ca_cert.not_valid_after}")
    print(f"    Is CA: True")
    
    print("\n[✓] Root CA generated successfully!")
    print("[!] Keep ca_key.pem secure - never commit to version control")


if __name__ == '__main__':
    generate_ca()
