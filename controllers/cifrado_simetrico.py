import os, re
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
BUNDLE_RE = re.compile(
    r"^\s*aescbc:key=([0-9a-fA-F]+);iv=([0-9a-fA-F]+);ct=([0-9a-fA-F]+)\s*$"
)

def generate_aes_key_iv() -> Tuple[bytes, bytes]:
    return os.urandom(32), os.urandom(16)  # 256-bit key, 128-bit IV

def _pkcs7_pad(data: bytes) -> bytes:
    pad = BLOCK - (len(data) % BLOCK)
    return data + bytes([pad] * pad)

def _pkcs7_unpad(padded: bytes) -> bytes:
    pad = padded[-1]
    if pad < 1 or pad > BLOCK or padded[-pad:] != bytes([pad]) * pad:
        raise ValueError("Padding inválido")
    return padded[:-pad]

def encrypt_text_aes_cbc(text: str, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    data = _pkcs7_pad(text.encode("utf-8"))
    return enc.update(data) + enc.finalize()

def decrypt_text_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return _pkcs7_unpad(padded)

# --------------------------
# Helpers para "paquete"
# --------------------------
def make_bundle(key: bytes, iv: bytes, ct: bytes) -> str:
    return f"aescbc:key={key.hex()};iv={iv.hex()};ct={ct.hex()}"

def parse_bundle(s: str) -> Optional[Tuple[bytes, bytes, bytes]]:
    m = BUNDLE_RE.match(s or "")
    if not m:
        return None
    k_hex, iv_hex, ct_hex = m.groups()
    return bytes.fromhex(k_hex), bytes.fromhex(iv_hex), bytes.fromhex(ct_hex)
