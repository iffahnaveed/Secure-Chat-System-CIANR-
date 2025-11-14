#!/usr/bin/env python3
"""
Generate X.509 certificates for server and client
Signs certificates with the Root CA
"""

import sys
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def load_ca():
    """Load CA certificate and private key"""
    # Load CA private key
    with open('certs/ca_key.pem', 'rb') as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open('certs/ca_cert.pem', 'rb') as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_private_key, ca_cert


def generate_certificate(entity_type):
    """
    Generate certificate for server or client
    
    Args:
        entity_type: 'server' or 'client'
    """
    if entity_type not in ['server', 'client']:
        print("Error: entity_type must be 'server' or 'client'")
        sys.exit(1)
    
    print(f"[*] Generating {entity_type} certificate...")
    
    # Load CA
    ca_private_key, ca_cert = load_ca()
    print(f"[+] Loaded CA certificate")
    
    # Generate RSA private key for entity
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create certificate subject
    if entity_type == 'server':
        common_name = u"securechat.server"
        dns_name = "localhost"
    else:
        common_name = u"securechat.client"
        dns_name = "client.localhost"
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Khyber Pakhtunkhwa"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Peshawar"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FAST NUCES"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build the certificate
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(dns_name),
            ]),
            critical=False,
        )
    )
    
    # Add Extended Key Usage based on entity type
    if entity_type == 'server':
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    else:
        cert_builder = cert_builder.add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    
    # Sign the certificate with CA
    cert = cert_builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Write private key to file
    key_filename = f'certs/{entity_type}_key.pem'
    with open(key_filename, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    print(f"[+] {entity_type.capitalize()} private key saved to {key_filename}")
    
    # Write certificate to file
    cert_filename = f'certs/{entity_type}_cert.pem'
    with open(cert_filename, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print(f"[+] {entity_type.capitalize()} certificate saved to {cert_filename}")
    
    # Display certificate info
    print(f"\n[*] {entity_type.capitalize()} Certificate Details:")
    print(f"    Subject: {cert.subject.rfc4514_string()}")
    print(f"    Issuer: {cert.issuer.rfc4514_string()}")
    print(f"    Serial Number: {cert.serial_number}")
    print(f"    Valid From: {cert.not_valid_before}")
    print(f"    Valid Until: {cert.not_valid_after}")
    print(f"    Common Name: {common_name}")
    
    print(f"\n[✓] {entity_type.capitalize()} certificate generated successfully!")


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python gen_cert.py <server|client>")
        sys.exit(1)
    
    entity_type = sys.argv[1].lower()
    
    # Check if CA exists
    if not os.path.exists('certs/ca_key.pem') or not os.path.exists('certs/ca_cert.pem'):
        print("Error: CA not found. Run gen_ca.py first.")
        sys.exit(1)
    
    generate_certificate(entity_type)
