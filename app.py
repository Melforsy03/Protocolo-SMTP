from flask import Flask, render_template, request
from Cliente import main  # Importa tu función de cliente SMTP

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # Renderiza el formulario

@app.route('/send', methods=['POST'])
def send_email():
    server = request.form.get('server', '127.0.0.1')  # Valor por defecto: 127.0.0.1
    port = int(request.form.get('port', 2525))  # Valor por defecto: 2525
    username = request.form['username']
    password = request.form['password']
    sender = request.form['sender']
    recipient = request.form['recipient']
    message = request.form['message']

    try:
        # Capturar los logs del cliente
        client_logs = main(server, port, username, password, sender, recipient, message)
        
        # Leer contenido del archivo TXT
        try:
         with open("emails.txt", "r") as file:
          server_logs = file.read()
          # Reemplazar caracteres "<" y ">" con cadenas limpias
          server_logs = server_logs.replace("<", "").replace(">", "")
        except FileNotFoundError:
         server_logs = "El archivo de correos no existe."


        return render_template(
            'index.html',
            client_logs=f"<pre>{client_logs}</pre>",
            server_logs=f"<pre>{server_logs}</pre>"
        )
    except Exception as e:
        return render_template(
            'index.html',
            client_logs="",
            server_logs=f"Error en el servidor: {str(e)}"
        )

if __name__ == '__main__':
    app.run(debug=True)
