import socket
import threading
import json
import os
import datetime

# Paramètres du serveur
HOST = '0.0.0.0'
PORT = 12345
clients = []  # Liste des (socket, username)
connected_users = set()  # Liste des utilisateurs connectés
muted_users = set()  # Liste des utilisateurs mutés
banned_users = set()  # Liste des utilisateurs bannis
user_data_file = "users.json"

# Création du dossier logs
if not os.path.exists("logs"):
    os.makedirs("logs")

# Création d'un fichier log unique pour chaque session
log_filename = f"logs/server_log_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

def log_action(action):
    """Enregistre une action dans le fichier log"""
    with open(log_filename, "a") as log_file:
        log_file.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {action}\n")

def load_users():
    """Charge les utilisateurs depuis le fichier JSON"""
    with open(user_data_file, "r") as f:
        return json.load(f)

def save_users(users):
    """Enregistre les utilisateurs dans le fichier JSON"""
    with open(user_data_file, "w") as f:
        json.dump(users, f, indent=4)

def register(client_socket):
    """Gère l'inscription"""
    client_socket.send(b"Enter username: ")
    username = client_socket.recv(1024).decode("utf-8").strip()
    
    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024).decode("utf-8").strip()

    users = load_users()
    if username in users:
        client_socket.send(b"Username already exists!\n")
        return None

    users[username] = password
    save_users(users)
    log_action(f"New user registered: {username}")
    client_socket.send(b"Registration successful!\n")
    return None

def login(client_socket):
    """Gère la connexion"""
    client_socket.send(b"Enter username: ")
    username = client_socket.recv(1024).decode("utf-8").strip()
    
    if username in banned_users:
        client_socket.send(b"You are banned from this server!\n")
        return None

    client_socket.send(b"Enter password: ")
    password = client_socket.recv(1024).decode("utf-8").strip()

    users = load_users()
    
    if username in connected_users:
        client_socket.send(b"User already logged in!\n")
        return None

    if users.get(username) == password:
        client_socket.send(b"Login successful!\n")
        connected_users.add(username)
        log_action(f"{username} logged in.")
        return username
    else:
        client_socket.send(b"Invalid credentials!\n")
        return None

def delete_account(client_socket, username):
    """Supprime le compte utilisateur"""
    users = load_users()
    
    if username in users:
        del users[username]
        save_users(users)
        connected_users.discard(username)
        log_action(f"{username} deleted their account.")
        client_socket.send(b"Account deleted. Goodbye!\n")
        return True
    else:
        client_socket.send(b"Error deleting account!\n")
        return False

def list_users(client_socket, username):
    """Affiche la liste des utilisateurs (admin seulement)"""
    if username != "admin":
        client_socket.send(b"Unauthorized command!\n")
        return
    
    users = load_users()
    user_list = "\n".join(users.keys())
    client_socket.send(f"Users:\n{user_list}\n".encode("utf-8"))

def send_help(client_socket):
    """Affiche la liste des commandes disponibles"""
    commands = """
    [COMMANDS]
    /help           - Affiche cette liste
    /logout         - Se déconnecter
    /whoami         - Affiche votre pseudo
    /online         - Affiche les utilisateurs connectés
    /changepass     - Changer son mot de passe
    /deleteaccount  - Supprimer son compte
    /listusers      - Lister les utilisateurs (admin seulement)
    """
    client_socket.send(commands.encode("utf-8"))

def handle_client(client_socket, addr):
    """Gère un client connecté"""
    print(f"[+] Nouvelle connexion de {addr}")

    username = None
    while not username:
        client_socket.send(b"Type 'login' to sign in or 'register' to create an account: ")
        choice = client_socket.recv(1024).decode("utf-8").strip().lower()

        if choice == "register":
            register(client_socket)
        elif choice == "login":
            username = login(client_socket)

    clients.append((client_socket, username))
    log_action(f"{username} connected from {addr}.")
    
    try:
        while True:
            message = client_socket.recv(1024).decode("utf-8")
            if not message:
                break
            
            if message.lower() == "/logout":
                break
            elif message.lower() == "/whoami":
                client_socket.send(f"Your username: {username}\n".encode("utf-8"))
            elif message.lower() == "/online":
                online_users = "\n".join(connected_users)
                client_socket.send(f"Online users:\n{online_users}\n".encode("utf-8"))
            elif message.lower() == "/help":
                send_help(client_socket)
            elif message.lower() == "/deleteaccount":
                if delete_account(client_socket, username):
                    break
            elif message.startswith("/"):
                client_socket.send(b"Unknown command. Type /help for a list of commands.\n")
            else:
                log_action(f"{username}: {message}")
                for client, uname in clients:
                    if client != client_socket:
                        try:
                            client.send(f"[{username}] {message}".encode("utf-8"))
                        except:
                            clients.remove((client, uname))

    except:
        pass

    print(f"[-] {username} ({addr}) déconnecté.")
    clients.remove((client_socket, username))
    connected_users.discard(username)
    log_action(f"{username} logged out.")
    client_socket.send(b"You have been logged out.\n")
    client_socket.close()

def start_server():
    """Lance le serveur"""
    log_action("Server started.")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Serveur démarré sur {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        thread.start()

if __name__ == "__main__":
    start_server()
