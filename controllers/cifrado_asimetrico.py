from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from pathlib import Path

KEY_DIR = Path("keys")
PRIV = KEY_DIR / "private_key.pem"
PUB = KEY_DIR / "public_key.pem"

def generate_rsa_keys():
    KEY_DIR.mkdir(exist_ok=True)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pem_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    PRIV.write_bytes(pem_private)
    PUB.write_bytes(pem_public)

def _load_keys():
    private_key = serialization.load_pem_private_key(PRIV.read_bytes(), password=None)
    public_key = serialization.load_pem_public_key(PUB.read_bytes())
    return private_key, public_key

def ensure_rsa_keys_exist():
    if not PRIV.exists() or not PUB.exists():
        generate_rsa_keys()

def rsa_encrypt(message: bytes) -> bytes:
    _, public_key = _load_keys()
    return public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )

def rsa_decrypt(ciphertext: bytes) -> bytes:
    private_key, _ = _load_keys()
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
