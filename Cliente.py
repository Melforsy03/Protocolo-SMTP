import socket
import base64
from cryptography.fernet import Fernet
import ssl
# Leer la clave de cifrado desde el archivo
with open("secret.key", "rb") as key_file:
    key = key_file.read()

cipher_suite = Fernet(key)
message = "This is a test email."
encrypted_message = cipher_suite.encrypt(message.encode())

def main(server, port, username, password, sender, recipient, message):
    # Crear contexto SSL para el cliente
    context = ssl.create_default_context()
    context.load_verify_locations("server.crt")
    
    encrypted_message = cipher_suite.encrypt(message.encode())
    logs = []  # Lista para registrar los logs

    try:
        with socket.create_connection((server, port)) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=server) as client_socket:
                # Registro del saludo inicial
                response = client_socket.recv(1024).decode()
                logs.append(f"Servidor: {response.strip()}")

                # Enviar comandos y registrar respuestas
                def send_command(sock, command):
                    sock.sendall(command.encode())
                    response = sock.recv(1024).decode()
                    logs.append(f"Cliente: {command.strip()}")
                    logs.append(f"Servidor: {response.strip()}")

                # Enviar comandos SMTP
                send_command(client_socket, "EHLO localhost\r\n")
                send_command(client_socket, "AUTH LOGIN\r\n")
                send_command(client_socket, base64.b64encode(username.encode()).decode() + "\r\n")
                send_command(client_socket, base64.b64encode(password.encode()).decode() + "\r\n")
                send_command(client_socket, f"MAIL FROM:<{sender}>\r\n")
                send_command(client_socket, f"RCPT TO:<{recipient}>\r\n")
                send_command(client_socket, "DATA\r\n")
                send_command(client_socket, f"{encrypted_message.decode()}\r\n.\r\n")
                
                # Cerrar la conexión con QUIT
                response = send_command(client_socket, "QUIT\r\n")
                print(response)
    except Exception as e:
        print(f"Error durante la conexión o cierre: {e}")
    finally:
        print("Conexión cerrada.")
    return "\n".join(logs)
if __name__ == "__main__":
    main()