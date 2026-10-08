from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def main():
    output_dir = Path("certs")
    output_dir.mkdir(exist_ok=True)
    private_key_path = Path(os.environ["LOCALAPPDATA"]) / "NetworkGuard" / "host-only.key"
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "NetworkGuard VirtualBox host")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ip_address("192.168.148.1"))]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    (output_dir / "host-only.crt").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"Created certs/host-only.crt for 192.168.148.1 and private key at {private_key_path}.")
    print("The private key is outside the OneDrive project folder. Copy only the .crt file to Linux Mint.")


if __name__ == "__main__":
    main()
