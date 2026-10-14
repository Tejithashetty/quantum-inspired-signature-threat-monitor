import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
KEYS = ROOT / "keys"
PRIVATE_FILE = KEYS / "private_key.pem"
PUBLIC_FILE = KEYS / "public_key.txt"


def main():
    KEYS.mkdir(exist_ok=True)
    if PRIVATE_FILE.exists():
        private_key = serialization.load_pem_private_key(PRIVATE_FILE.read_bytes(), password=None)
    else:
        private_key = Ed25519PrivateKey.generate()
        PRIVATE_FILE.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        PRIVATE_FILE.chmod(0o600)
        PUBLIC_FILE.write_text(base64.b64encode(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )).decode("ascii"), encoding="utf-8")
        print("Created a local key pair. Keep keys/private_key.pem secret and never upload it.")
    message = input("Type the message to sign: ")
    signature = private_key.sign(message.encode("utf-8"))
    public_key = base64.b64encode(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")
    print("Copy this JSON into the POST /api/events request body:")
    print(json.dumps({"message": message, "public_key": public_key, "signature": base64.b64encode(signature).decode("ascii")}, indent=2))

if __name__ == "__main__":
    main()
