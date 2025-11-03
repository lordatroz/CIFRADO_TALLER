import os
from flask import Flask, render_template, request, send_file, flash
from werkzeug.utils import secure_filename

# --- Simétrico (ya implementado con paquete aescbc:key=..;iv=..;ct=..) ---
from controllers.cifrado_simetrico import (
    encrypt_text_aes_cbc, decrypt_text_aes_cbc, generate_aes_key_iv,
    make_bundle, parse_bundle
)

# --- Asimétrico (RSA) ---
from controllers.cifrado_asimetrico import (
    generate_rsa_keys, rsa_encrypt, rsa_decrypt, ensure_rsa_keys_exist
)

# --- Hashes ---
from controllers.funcion_hash import sha256_string, sha256_file

# --- Archivos (AES-GCM) con flujo ZIP simple + modo avanzado opcional ---
from controllers.cifrado_archivos import (
    file_encrypt_aesgcm_to_zip,
    file_decrypt_aesgcm_from_zip,
    file_encrypt_aesgcm,
    file_decrypt_aesgcm,
)

app = Flask(__name__, static_folder="static", template_folder="templates")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-super-secret-key")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", 10 * 1024 * 1024))  # 10MB

BASE_DIR = os.getcwd()
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ---------------------------------------------------------------------
# HOME
# ---------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------------------------------------------------------------------
# CIFRADO SIMÉTRICO (AES-CBC + paquete)
# ---------------------------------------------------------------------
@app.route("/cifrado_simetrico", methods=["GET", "POST"])
def cifrado_simetrico():
    result = {}
    if request.method == "POST":
        action = request.form.get("action")

        if action == "encrypt":
            text = request.form.get("texto_plain", "").strip()
            if not text:
                flash("Escribe un texto para cifrar.", "error")
            else:
                key, iv = generate_aes_key_iv()
                ct = encrypt_text_aes_cbc(text, key, iv)
                result = {
                    "mode": "encrypt",
                    "key": key.hex(),
                    "iv": iv.hex(),
                    "ciphertext": ct.hex(),
                    "bundle": make_bundle(key, iv, ct),
                }

        elif action == "decrypt_bundle":
            bundle = request.form.get("bundle", "").strip()
            triple = parse_bundle(bundle)
            if not triple:
                flash("Formato de paquete inválido. Usa: aescbc:key=<hex>;iv=<hex>;ct=<hex>", "error")
            else:
                key, iv, ct = triple
                try:
                    pt = decrypt_text_aes_cbc(ct, key, iv).decode("utf-8", errors="ignore")
                    result = {"mode": "decrypt", "plaintext": pt}
                except Exception as e:
                    flash(f"Error al descifrar (paquete): {e}", "error")

        elif action == "decrypt_advanced":
            try:
                key_hex = request.form.get("key_hex", "").strip()
                iv_hex = request.form.get("iv_hex", "").strip()
                ct_hex = request.form.get("ct_hex", "").strip()
                pt = decrypt_text_aes_cbc(bytes.fromhex(ct_hex), bytes.fromhex(key_hex), bytes.fromhex(iv_hex))
                result = {"mode": "decrypt", "plaintext": pt.decode("utf-8", errors="ignore")}
            except Exception as e:
                flash(f"Error al descifrar (avanzado): {e}", "error")

    return render_template("cifrado_simetrico.html", result=result)

# ---------------------------------------------------------------------
# CIFRADO ASIMÉTRICO (RSA OAEP) + paquete rsaoaep:ct=<hex>
# ---------------------------------------------------------------------
@app.route("/cifrado_asimetrico", methods=["GET", "POST"])
def cifrado_asimetrico():
    ensure_rsa_keys_exist()
    result = {}
    if request.method == "POST":
        action = request.form.get("action")

        if action == "encrypt":
            msg = request.form.get("mensaje", "").encode("utf-8")
            if not msg:
                flash("Escribe un mensaje para cifrar.", "error")
            else:
                ct_hex = rsa_encrypt(msg).hex()
                # Paquete simple (solo ciphertext hex). La clave pública ya está guardada en /keys
                result = {
                    "mode": "encrypt",
                    "ciphertext_hex": ct_hex,
                    "bundle": f"rsaoaep:ct={ct_hex}"
                }

        elif action == "decrypt_bundle":
            bundle = request.form.get("bundle", "").strip()
            if not bundle.startswith("rsaoaep:ct="):
                flash("Formato inválido. Usa: rsaoaep:ct=<hex>", "error")
            else:
                ct_hex = bundle.split("rsaoaep:ct=", 1)[1].strip()
                try:
                    pt = rsa_decrypt(bytes.fromhex(ct_hex)).decode("utf-8", errors="ignore")
                    result = {"mode": "decrypt", "plaintext": pt}
                except Exception as e:
                    flash(f"Error al descifrar (paquete RSA): {e}", "error")

        elif action == "decrypt_raw":
            try:
                ct_hex = request.form.get("ciphertext_hex", "").strip()
                pt = rsa_decrypt(bytes.fromhex(ct_hex)).decode("utf-8", errors="ignore")
                result = {"mode": "decrypt", "plaintext": pt}
            except Exception as e:
                flash(f"Error al descifrar (hex): {e}", "error")

    return render_template("cifrado_asimetrico.html", result=result)

# ---------------------------------------------------------------------
# FUNCIONES HASH (SHA-256) + verificación simple
# ---------------------------------------------------------------------
@app.route("/funcion_hash", methods=["GET", "POST"])
def funcion_hash():
    result = {}
    if request.method == "POST":
        mode = request.form.get("mode")

        # Hash de texto
        if mode == "text":
            txt = request.form.get("texto", "")
            result["text_hash"] = sha256_string(txt)

        # Hash de archivo
        elif mode == "file":
            f = request.files.get("archivo")
            if f and f.filename:
                path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
                f.save(path)
                result["file_name"] = f.filename
                result["file_hash"] = sha256_file(path)
            else:
                flash("Adjunta un archivo.", "error")

        # Verificar hash de texto (pegar esperado)
        elif mode == "verify_text":
            txt = request.form.get("texto_verif", "")
            expected = request.form.get("hash_esperado_texto", "").strip().lower()
            got = sha256_string(txt)
            result["verify_text_ok"] = (expected == got) if expected else None
            result["verify_text_expected"] = expected
            result["verify_text_got"] = got

        # Verificar hash de archivo (subir archivo + pegar esperado)
        elif mode == "verify_file":
            f = request.files.get("archivo_verif")
            expected = request.form.get("hash_esperado_archivo", "").strip().lower()
            if f and f.filename:
                path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
                f.save(path)
                got = sha256_file(path)
                result["verify_file_name"] = f.filename
                result["verify_file_ok"] = (expected == got) if expected else None
                result["verify_file_expected"] = expected
                result["verify_file_got"] = got
            else:
                flash("Adjunta el archivo a verificar.", "error")

    return render_template("funcion_hash.html", result=result)

# ---------------------------------------------------------------------
# CIFRADO / DESCIFRADO DE ARCHIVOS (AES-GCM)
# ---------------------------------------------------------------------
@app.route("/cifrado_archivos", methods=["GET", "POST"])
def cifrado_archivos():
    result = {}
    if request.method == "POST":
        mode = request.form.get("mode", "zip")  # zip | advanced
        action = request.form.get("action")

        # -------- MODO ZIP (simple) --------
        if mode == "zip":
            if action == "encrypt":
                f = request.files.get("archivo_zip_enc")
                if not (f and f.filename):
                    flash("Selecciona un archivo para cifrar.", "error")
                    return render_template("cifrado_archivos.html", result=result)

                in_path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
                f.save(in_path)

                zip_name = f"{os.path.splitext(f.filename)[0]}_cifrado.zip"
                zip_path = os.path.join(OUTPUT_DIR, zip_name)
                file_encrypt_aesgcm_to_zip(in_path, zip_path)
                return send_file(zip_path, as_attachment=True, download_name=zip_name)

            elif action == "decrypt":
                zf = request.files.get("archivo_zip_dec")
                if not (zf and zf.filename.endswith(".zip")):
                    flash("Sube el ZIP que descargaste al cifrar.", "error")
                    return render_template("cifrado_archivos.html", result=result)

                zip_in = os.path.join(UPLOAD_DIR, secure_filename(zf.filename))
                zf.save(zip_in)

                out_name = request.form.get("nombre_salida", "").strip()
                if not out_name:
                    base = os.path.splitext(zf.filename)[0]
                    out_name = f"{base}_recuperado"
                out_path = os.path.join(OUTPUT_DIR, out_name)

                try:
                    file_decrypt_aesgcm_from_zip(zip_in, out_path)
                    return send_file(out_path, as_attachment=True, download_name=os.path.basename(out_path))
                except Exception as e:
                    flash(f"Error al descifrar ZIP: {e}", "error")

        # -------- MODO AVANZADO (dos inputs) --------
        elif mode == "advanced":
            if action == "encrypt":
                f = request.files.get("archivo_enc")
                if not (f and f.filename):
                    flash("Selecciona un archivo para cifrar.", "error")
                    return render_template("cifrado_archivos.html", result=result)

                in_path = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
                f.save(in_path)
                out_enc = os.path.join(OUTPUT_DIR, f"{os.path.splitext(f.filename)[0]}.enc")
                out_key = os.path.join(OUTPUT_DIR, f"{os.path.splitext(f.filename)[0]}.key")
                file_encrypt_aesgcm(in_path, out_enc, out_key)
                return send_file(out_enc, as_attachment=True, download_name=os.path.basename(out_enc))

            elif action == "decrypt":
                encf = request.files.get("archivo_dec")
                keyf = request.files.get("keyfile")
                if not (encf and keyf and encf.filename.endswith(".enc") and keyf.filename.endswith(".key")):
                    flash("Sube el .enc y el .key para descifrar (modo avanzado).", "error")
                    return render_template("cifrado_archivos.html", result=result)

                in_enc = os.path.join(UPLOAD_DIR, secure_filename(encf.filename))
                in_key = os.path.join(UPLOAD_DIR, secure_filename(keyf.filename))
                encf.save(in_enc)
                keyf.save(in_key)

                out_name = f"{os.path.splitext(encf.filename)[0]}_dec"
                out_path = os.path.join(OUTPUT_DIR, out_name)
                try:
                    file_decrypt_aesgcm(in_enc, out_path, in_key)
                    return send_file(out_path, as_attachment=True, download_name=os.path.basename(out_path))
                except Exception as e:
                    flash(f"Error al descifrar (avanzado): {e}", "error")

    return render_template("cifrado_archivos.html", result=result)

if __name__ == "__main__":
    # Puerto alterno para no chocar con 5000/8000
    app.run(debug=True, host="0.0.0.0", port=5173)
