from cryptography.hazmat.primitives import hashes

def sha256_string(text: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(text.encode("utf-8"))
    return digest.finalize().hex()

def sha256_file(path: str) -> str:
    digest = hashes.Hash(hashes.SHA256())
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            digest.update(chunk)
    return digest.finalize().hex()
