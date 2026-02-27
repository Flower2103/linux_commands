# Linux Command API

**Proyecto escolar**
API REST desarrollada en Flask que permite ejecutar comandos Linux predefinidos de forma segura, con autenticación basada en usuarios reales del sistema operativo.

## Creadores
- Alejandra Rodriguez
- Flor Mayon

## 🎯Objetivo General
Desarrollar una API REST que permita ejecutar comandos Linux predefinidos en el servidor, implementando controles estrictos de seguridad para prevenir vulnerabilidades como Command Injection, acceso no autorizado y ejecución arbitraria de código.
El servidor ya cuenta con un usuario Linux limitado, por lo que el sistema deberá operar bajo el principio de menor privilegio.
Se debe construir una API que permita ejecutar únicamente comandos autorizados del sistema operativo Linux, devolviendo la salida en formato JSON.

## 📋Requisitos

- Python 3.10+
- Ubuntu
- Usuario Linux limitado

## Entorno de desarrollo
- OS: Ubuntu Server 24.04 LTS
- Virtualización: VirtualBox

## ⚙️Instalación

```bash
git clone <https://github.com/Flower2103/linux_commands.git>
cd linux_commands
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 💻Levantar el servidor

El servidor debe correrse con el usuario limitado  para cumplir el principio de menor privilegio:

```bash
su - usuario_limitado
cd /home/ada/linux_commands
source venv/bin/activate
export SECRET_KEY="define_password"
python app.py
```

## Uso

### 1. Obtener token

```bash
curl -X POST http://localhost:8000/auth/token \
  -F "username=tu_usuario" \
  -F "password=tu_contraseña"
```

Respuesta:
```json
{
  "access_token": "eyJ...",
  "token_type": "bearer"
}
```

### 2. Ejecutar comando

```bash
curl -X POST http://localhost:8000/system/execute \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime", "params": []}'
```

Respuesta:
```json
{
  "command": "uptime",
  "params": [],
  "stdout": " 23:10:15 up 1:56, 7 users, load average: 0.13, 0.08, 0.01\n",
  "stderr": "",
  "exit_code": 0,
  "executed_by": "usuario"
}
```

## Comandos disponibles

Los comandos autorizados se definen en el diccionario `ALLOWED_COMMANDS` dentro de `app.py`. Solo los comandos registrados ahí pueden ejecutarse — cualquier otro recibe un error `403`.

```python
ALLOWED_COMMANDS = {
    "uptime":   {"bin": "/usr/bin/uptime",  "params": []},
    "df":       {"bin": "/bin/df",          "params": ["-h", "-H", "--total"]},
    "free":     {"bin": "/usr/bin/free",    "params": ["-h", "-m", "-g"]},
    ...
}
```

Para agregar un nuevo comando, solo añade una entrada al diccionario con su ruta absoluta y los parámetros permitidos.

| Comando | Descripción | Parámetros permitidos |
|---|---|---|
| `uptime` | Tiempo de actividad del servidor | ninguno |
| `df` | Uso del disco | `-h`, `-H`, `--total` |
| `free` | Uso de RAM y swap | `-h`, `-m`, `-g` |
| `whoami` | Usuario con el que corre la API | ninguno |
| `hostname` | Nombre del servidor | ninguno |
| `uname` | Información del kernel | `-a`, `-r`, `-m` |
| `date` | Fecha y hora del sistema | ninguno |
| `ps` | Procesos en ejecución | `aux`, `-ef` |
| `lscpu` | Información de la CPU | ninguno |

## Seguridad

| Vulnerabilidad | Control |
|---|---|
| Command Injection | `shell=False` + argv como lista |
| Ejecución arbitraria | Whitelist de comandos y parámetros en `ALLOWED_COMMANDS` |
| Acceso no autorizado | JWT con expiración de 30 minutos |
| Escalada de privilegios | Servidor corre con usuario limitado `user` |
| Entorno inseguro | Subprocesos con `PATH` mínimo |

## Pruebas

```bash
# Sin token → 401
curl -X POST http://localhost:8000/system/execute \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime", "params": []}'

# Comando no autorizado → 403
curl -X POST http://localhost:8000/system/execute \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "params": []}'

# Parámetro no permitido → 400
curl -X POST http://localhost:8000/system/execute \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"command": "df", "params": ["-z"]}'

# Intento de injection → 403
curl -X POST http://localhost:8000/system/execute \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  -d '{"command": "uptime; rm -rf /", "params": []}'
```
