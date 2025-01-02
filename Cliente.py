import socket
from cryptography.fernet import Fernet
import base64

SMTP_SERVER = "127.0.0.1"
SMTP_PORT = 2525
MAIL_FROM = "sender@example.com"
RCPT_TO = "recipient@example.com"
USERNAME = "user"
PASSWORD = "password"
MESSAGE = """\
From: sender@example.com
To: recipient@example.com
Subject: Test Email with STARTTLS

Hello, this email was sent securely with STARTTLS.
"""
# Generar una clave y cifrar el mensaje
# Leer la clave de cifrado desde el archivo
with open("secret.key", "rb") as key_file:
    key = key_file.read()
cipher_suite = Fernet(key)
message = "This is a test email."
encrypted_message = cipher_suite.encrypt(message.encode())
def send_command(sock, command):
    sock.sendall(command.encode())
    response = sock.recv(1024).decode()
    print(response)
    return response

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("127.0.0.1", 2525))

    # Recibir mensaje de bienvenida
    response = client_socket.recv(1024).decode()
    print(response)

    # Enviar comandos SMTP
    send_command(client_socket, "HELO localhost\r\n")
    
    # Autenticación
    send_command(client_socket, "AUTH LOGIN\r\n")
    send_command(client_socket, base64.b64encode(b"user").decode() + "\r\n")
    send_command(client_socket, base64.b64encode(b"password").decode() + "\r\n")
    
    send_command(client_socket, "MAIL FROM:<sender@example.com>\r\n")
    send_command(client_socket, "RCPT TO:<recipient@example.com>\r\n")
    send_command(client_socket, "DATA\r\n")
    send_command(client_socket, f"{encrypted_message.decode()}\r\n.\r\n")
    send_command(client_socket, "QUIT\r\n")

    client_socket.close()

if __name__ == "__main__":
    main()