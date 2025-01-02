import threading
from app import app  # Importa tu app Flask
from Servidor import run_smtp_server  # Importa la función para iniciar el servidor SMTP

def run_flask():
    app.run(host='127.0.0.1', port=5000, debug=True)

if __name__ == "__main__":
    # Crea un hilo para ejecutar el servidor SMTP
    smtp_thread = threading.Thread(target=run_smtp_server, daemon=True)
    smtp_thread.start()

    # Ejecuta Flask en el hilo principal
    run_flask()
