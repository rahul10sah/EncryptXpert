import sys, os
from pathlib import Path
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
CA_DIR = DATA_DIR / "ca"
USER_DIR = DATA_DIR / "users" / "student1"

CA_DIR.mkdir(parents=True, exist_ok=True)
USER_DIR.mkdir(parents=True, exist_ok=True)

# ---------- CREATE / LOAD CA ----------
ca_key_path = CA_DIR / "ca_private_key.pem"
ca_cert_path = CA_DIR / "ca_certificate.pem"

if ca_key_path.exists() and ca_cert_path.exists():
    ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
else:
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    ca_subject = x509.Name([
        NameOID.COUNTRY_NAME and x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EncryptXpert"),
        x509.NameAttribute(NameOID.COMMON_NAME, "EncryptXpert Local Root CA"),
    ])

    now = datetime.now(timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ca_cert_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))


# ---------- CREATE USER ----------
user_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

user_subject = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "NP"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EncryptXpert Users"),
    x509.NameAttribute(NameOID.COMMON_NAME, "student1"),
])

now = datetime.now(timezone.utc)
user_cert = (
    x509.CertificateBuilder()
    .subject_name(user_subject)
    .issuer_name(ca_cert.subject)
    .public_key(user_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=825))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(ca_key, hashes.SHA256())
)

# ---------- CREATE PKCS#12 ----------
p12_password = b"Student@123"

p12_data = pkcs12.serialize_key_and_certificates(
    name=b"EncryptXpert-student1",
    key=user_key,
    cert=user_cert,
    cas=[ca_cert],
    encryption_algorithm=serialization.BestAvailableEncryption(p12_password),
)

(USER_DIR / "identity.p12").write_bytes(p12_data)
(USER_DIR / "certificate.pem").write_bytes(user_cert.public_bytes(serialization.Encoding.PEM))
(USER_DIR / "public_key.pem").write_bytes(
    user_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
)

print("✅ identity.p12 created successfully")
print("Password:", p12_password.decode())
print("Path:", USER_DIR / "identity.p12")
