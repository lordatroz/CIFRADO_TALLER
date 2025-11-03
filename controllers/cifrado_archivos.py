import os, json, zipfile, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12

def file_encrypt_aesgcm_to_zip(in_path: str, zip_out_path: str):
    """
    Cifra el archivo de entrada y genera un ZIP con:
      - <name>.enc (nonce + ciphertext)
      - <name>.key (json con clave hex)
    """
    src = Path(in_path)
    data = src.read_bytes()

    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)

    enc_name = f"{src.stem}.enc"
    key_name = f"{src.stem}.key"

    with zipfile.ZipFile(zip_out_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        # Guardar binario: nonce + ciphertext
        with z.open(enc_name, "w") as f:
            f.write(nonce + ct)
        # Guardar clave como JSON
        meta = {"k": key.hex()}
        z.writestr(key_name, json.dumps(meta), compress_type=zipfile.ZIP_DEFLATED)

def file_decrypt_aesgcm_from_zip(zip_path: str, out_path: str):
    """
    Descifra leyendo <*.enc> y <*.key> desde un ZIP.
    out_path es el archivo de salida (recuperado).
    """
    with zipfile.ZipFile(zip_path, "r") as z:
        # Buscar .enc y .key
        enc_member = next((n for n in z.namelist() if n.endswith(".enc")), None)
        key_member = next((n for n in z.namelist() if n.endswith(".key")), None)
        if not enc_member or not key_member:
            raise ValueError("El ZIP debe contener .enc y .key")

        blob = z.read(enc_member)
        nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
        meta = json.loads(z.read(key_member).decode("utf-8"))
        key = bytes.fromhex(meta["k"])

        data = AESGCM(key).decrypt(nonce, ct, associated_data=None)
        Path(out_path).write_bytes(data)

# --- modo avanzado opcional (.enc + .key separados) ---
def file_encrypt_aesgcm(in_path: str, out_enc_path: str, out_key_path: str):
    data = Path(in_path).read_bytes()
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct = aesgcm.encrypt(nonce, data, associated_data=None)

    Path(out_enc_path).write_bytes(nonce + ct)
    Path(out_key_path).write_text(json.dumps({"k": key.hex()}), encoding="utf-8")

def file_decrypt_aesgcm(in_enc_path: str, out_path: str, key_path: str):
    blob = Path(in_enc_path).read_bytes()
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    meta = json.loads(Path(key_path).read_text(encoding="utf-8"))
    key = bytes.fromhex(meta["k"])
    data = AESGCM(key).decrypt(nonce, ct, associated_data=None)
    Path(out_path).write_bytes(data)
