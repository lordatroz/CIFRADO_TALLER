# 🛡️ Taller de Cifrado — Flask · Cryptography · TailwindCSS

Proyecto académico desarrollado para el **Diplomado en Ciberseguridad**
**Universitaria de Colombia – Ingeniería de Sistemas (2025)**
**Autores:** Juan Esteban Ríos · Carlos Daniel Contreras

---

## 📘 Descripción General

Aplicación web construida con **Flask** que permite experimentar y comprender los principales mecanismos de **cifrado y seguridad de datos** en Python, aplicados a:

- 🔒 **Cifrado Simétrico (AES-CBC con PKCS#7)**
- 🔐 **Cifrado Asimétrico (RSA 2048 + OAEP SHA-256)**
- 🧩 **Funciones Hash (SHA-256)** para textos y archivos
- 📁 **Cifrado/Descifrado de Archivos (AES-GCM)**
- 📊 Interfaz web con **TailwindCSS**, **JavaScript** y diseño intuitivo

Cada módulo muestra visualmente el proceso y los resultados, permitiendo copiar o verificar los datos generados fácilmente.

---

## ⚙️ Tecnologías Utilizadas

- **Backend:** Python 3.10+ con Flask
- **Criptografía:** [cryptography](https://cryptography.io/en/latest/)
- **Frontend:** TailwindCSS + HTML + Jinja2
- **Servidor:** WSL2 (Ubuntu 22.04)
- **Control de versiones:** Git + GitHub

---

## 🧰 Instalación y Configuración

### 1️⃣ Clonar el repositorio

```bash
git clone https://github.com/lordatroz/CIFRADO_TALLER.git
cd CIFRADO_TALLER

2️⃣ Crear y activar el entorno virtual

python3 -m venv venv
source venv/bin/activate   # En Linux/WSL
# o .\venv\Scripts\activate en Windows

3️⃣ Instalar dependencias

pip install -r requirements.txt

4️⃣ Ejecutar el servidor Flask

flask run --host=0.0.0.0 --port=5173
Luego abre tu navegador en
👉 http://127.0.0.1:5173

🧩 Estructura del Proyecto

CIFRADO_TALLER/
├── app.py                        # Archivo principal Flask
├── controllers/                  # Lógica de cifrado y funciones auxiliares
│   ├── cifrado_simetricO.py
│   ├── cifrado_asimetrico.py
│   ├── cifrado_archivos.py
│   └── funcion_hash.py
├── templates/                    # Plantillas HTML (Jinja2)
│   ├── base.html
│   ├── index.html
│   ├── cifrado_simetrico.html
│   ├── cifrado_asimetrico.html
│   ├── funcion_hash.html
│   └── cifrado_archivos.html
├── static/
│   ├── style.css
│   └── complements.js
├── .env
├── .gitignore
├── README.md
└── requirements.txt


💻 Uso del Sistema
Módulo	Descripción
Cifrado Simétrico (AES-CBC)	Genera clave e IV automáticos, cifra texto, y produce un paquete reutilizable (aescbc:key=...;iv=...;ct=...).
Cifrado Asimétrico (RSA)	Cifra texto con clave pública RSA 2048 y permite descifrar usando la privada.
Funciones Hash (SHA-256)	Calcula el hash de textos o archivos, y permite verificar su integridad.
Cifrado de Archivos (AES-GCM)	Cifra y descifra archivos pequeños mediante un ZIP autocompleto (.zip con .enc y .key).

🎨 Interfaz y Diseño
TailwindCSS: estilos minimalistas, fondo oscuro y tipografía moderna.
JS: botones interactivos y copia rápida de resultados.
Navbar y Footer con información académica y enlaces a cada módulo.

📂 Resultados Esperados
Los textos cifrados se muestran en hexadecimal.
Los hashes generados pueden ser verificados manualmente o mediante “paquetes”.
Los archivos cifrados se descargan automáticamente.
Los errores y confirmaciones se muestran mediante alertas visuales.

🧾 Créditos
Proyecto: Taller de Cifrado de Datos
Autores:
Juan Esteban Ríos
Carlos Daniel Contreras
Universidad: Universitaria de Colombia
Programa: Ingeniería de Sistemas
Asignatura: Diplomado en Ciberseguridad
Año: 2025

🧠 Notas Técnicas
Claves RSA generadas automáticamente en la carpeta /keys/.
Límite máximo de subida: 10 MB (configurable en .env).
Código modular y comentado, con estructura MVC simplificada.
Compatible con WSL2, Linux y Windows.

📜 Licencia
Este proyecto fue desarrollado con fines académicos y educativos.
No se recomienda su uso en entornos de producción.
```
