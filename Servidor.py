import asyncio
import logging
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import ssl

HOST = "127.0.0.1"
PORT = 2525
EMAIL_REGEX = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
MAX_EMAIL_SIZE = 52428800  # 50 MB

# Credenciales de usuario para autenticación
VALID_USERNAME = "user"
VALID_PASSWORD = "password"

# Configuración de fuerza bruta
MAX_FAILED_ATTEMPTS = 3
BLOCK_TIME = timedelta(minutes=5)
failed_attempts = {}

def is_blocked(client_address):
    # Verificar si la IP está bloqueada
    if client_address in failed_attempts:
        attempts, block_time = failed_attempts[client_address]
        if attempts >= MAX_FAILED_ATTEMPTS and datetime.now() < block_time:
            return True
        elif datetime.now() >= block_time:
            del failed_attempts[client_address]  # Desbloquear IP
    return False

def register_failed_attempt(client_address):
    if client_address not in failed_attempts:
        failed_attempts[client_address] = [0, datetime.now()]
    failed_attempts[client_address][0] += 1
    if failed_attempts[client_address][0] >= MAX_FAILED_ATTEMPTS:
        failed_attempts[client_address][1] = datetime.now() + BLOCK_TIME
        
# Configuración de logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# Leer la clave de cifrado desde el archivo
with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher_suite = Fernet(key)


async def handle_client(reader, writer):
    client_address = writer.get_extra_info("peername")
    logging.info(f"Conexión establecida desde {client_address}")

    writer.write(b"220 localhost Simple SMTP Server Ready\r\n")
    await writer.drain()

    mail_from = None
    rcpt_to = None
    data_mode = False
    email_data = []
    authenticated = False

    while True:
        try:
            # Leer comando del cliente
            data = await reader.readline()
            if not data:
                logging.warning(f"Cliente {client_address} cerró la conexión.")
                break
            command = data.decode("utf-8").strip()
            logging.info(f"Cliente {client_address}: {command}")

            if not authenticated:
                if command.upper().startswith("AUTH LOGIN"):
                    writer.write(b"334 VXNlcm5hbWU6\r\n")  # Base64 de "Username:"
                    await writer.drain()
                    username = (await reader.readline()).decode("utf-8").strip()
                    writer.write(b"334 UGFzc3dvcmQ6\r\n")  # Base64 de "Password:"
                    await writer.drain()
                    password = (await reader.readline()).decode("utf-8").strip()

                    if (base64.b64decode(username).decode("utf-8") == VALID_USERNAME and
                            base64.b64decode(password).decode("utf-8") == VALID_PASSWORD):
                        authenticated = True
                        writer.write(b"235 Authentication successful\r\n")
                        await writer.drain()
                        continue
                    else:
                        writer.write(b"535 Authentication failed\r\n")
                        await writer.drain()
                        break
                else:
                    writer.write(b"530 Authentication required\r\n")
                    await writer.drain()
                    continue

            if data_mode:
                if command == ".":
                    if len("\n".join(email_data)) > MAX_EMAIL_SIZE:
                        writer.write(b"552 Message size exceeds limit\r\n")
                    else:
                        # Descifrar el mensaje
                        try:
                            decrypted_message = cipher_suite.decrypt("\n".join(email_data).encode()).decode()
                            logging.info(f"Correo recibido de {client_address}:\n{decrypted_message}")
                            save_email(mail_from, rcpt_to, decrypted_message)
                            writer.write(b"250 OK\r\n") 
                        except Exception as e:
                            logging.error(f"Error al descifrar el mensaje: {e}")
                            writer.write(b"550 Failed to decrypt message\r\n")
                    email_data = []
                    data_mode = False
                else:
                    email_data.append(command)
            else:
                if command.upper().startswith("MAIL FROM:"):
                    mail_from = command[10:].strip()
                    writer.write(b"250 OK\r\n")
                elif command.upper().startswith("RCPT TO:"):
                    rcpt_to = command[8:].strip()
                    writer.write(b"250 OK\r\n")
                elif command.upper() == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    data_mode = True
                elif command.upper() == "QUIT":
                    writer.write(b"221 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"500 Syntax error, command unrecognized\r\n")
            await writer.drain()
        except Exception as e:
            logging.error(f"Error con el cliente {client_address}: {e}")
            break

    logging.info(f"Conexión cerrada con {client_address}")
    writer.close()
    await writer.wait_closed()


def save_email(mail_from, rcpt_to, email_data):
    with open("emails.txt", "a") as f:
        f.write(f"From: {mail_from}\n")
        f.write(f"To: {rcpt_to}\n")
        f.write(f"{email_data}\n\n")


async def start_server():
 # Crear contexto SSL
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Requiere certificados

    # Iniciar servidor con SSL
    server = await asyncio.start_server(handle_client, HOST, PORT, ssl=ssl_context)
    logging.info(f"Servidor SMTP escuchando en {HOST}:{PORT} con TLS...")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(start_server())