"""
Linux Command API - Flask
POST /auth/token     → obtener JWT con usuario Linux
POST /system/execute → ejecutar comando autorizado
"""

import os
import subprocess
import logging
import pam
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify
from jose import JWTError, jwt

# ─── Configuración ─────────────────────────────────────────────

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY no está definida en las variables de entorno.")

ALGORITHM = "HS256"
TOKEN_EXP_MINUTES = 30
CMD_TIMEOUT = 10  # segundos máximo por comando

# ─── Lista blanca de comandos autorizados ─────────────────────

ALLOWED_COMMANDS = {
    "uptime":   {"bin": "/usr/bin/uptime",  "params": []},
    "df":       {"bin": "/bin/df",          "params": ["-h", "-H", "--total"]},
    "free":     {"bin": "/usr/bin/free",    "params": ["-h", "-m", "-g"]},
    "whoami":   {"bin": "/usr/bin/whoami",  "params": []},
    "hostname": {"bin": "/bin/hostname",    "params": []},
    "uname":    {"bin": "/bin/uname",       "params": ["-a", "-r", "-m"]},
    "date":     {"bin": "/bin/date",        "params": []},
    "ps":       {"bin": "/bin/ps",          "params": ["aux", "-ef"]},
    "lscpu":    {"bin": "/usr/bin/lscpu",   "params": []},
}

# ─── Logging ──────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("api")

# ─── Inicializar Flask ─────────────────────────────────────────

app = Flask(__name__)

# ─── Autenticación contra usuario Linux (PAM) ──────────────────

def linux_login(username: str, password: str) -> bool:
    if not re.match(r"^[a-zA-Z0-9_\-]{1,32}$", username):
        return False
    
    p = pam.pam()
  
    res = p.authenticate(username, password, service="login")
    
    if not res:
        print(f" FALLO PAM: {p.reason} | Código: {p.code}")
        
    return res


def make_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXP_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Token requerido."}), 401

        token = auth.split(" ", 1)[1]

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            request.current_user = data["sub"]
        except JWTError:
            return jsonify({"error": "Token inválido o expirado."}), 401

        return f(*args, **kwargs)
    return wrapper

# ─── Rutas ─────────────────────────────────────────────────────

@app.post("/auth/token")
def login():
    data = request.form
    username = data.get("username", "")
    password = data.get("password", "")

    if not linux_login(username, password):
        log.warning("Login fallido: %s", username)
        return jsonify({"error": "Credenciales incorrectas."}), 401

    log.info("Login exitoso: %s", username)
    return jsonify({
        "access_token": make_token(username),
        "token_type": "bearer"
    })


@app.post("/system/execute")
@require_auth
def execute():
    body = request.get_json(silent=True) or {}
    command = body.get("command", "")
    params = body.get("params", [])

    # Validar que params sea lista
    if not isinstance(params, list):
        return jsonify({"error": "Params debe ser una lista."}), 400

    # Verificar comando en lista blanca
    cfg = ALLOWED_COMMANDS.get(command)
    if not cfg:
        return jsonify({"error": f"Comando '{command}' no autorizado."}), 403

    # Validar parámetros permitidos
    for p in params:
        if p not in cfg["params"]:
            return jsonify({
                "error": f"Parámetro '{p}' no permitido para '{command}'."
            }), 400

    argv = [cfg["bin"]] + params
    log.info("Ejecutando [%s]: %s", request.current_user, argv)

    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=CMD_TIMEOUT,
            shell=False,                    # Previene Command Injection
            env={"PATH": "/usr/bin:/bin"},  # Entorno controlado
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Timeout al ejecutar el comando."}), 408

    return jsonify({
        "command": command,
        "params": params,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "exit_code": result.returncode,
        "executed_by": request.current_user,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
