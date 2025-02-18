import socket
import threading
import json
import os
import datetime

# Paramètres du serveur
HOST = '127.0.0.1'
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

def logout(client_socket, username):
    """Gère la déconnexion de l'utilisateur"""
    log_action(f"{username} logged out.")
    clients.remove((client_socket, username))
    connected_users.discard(username)
    client_socket.send(b"You have been logged out.\n")
    client_socket.close()

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
    /mute <user>    - Mute un utilisateur (admin)
    /unmute <user>  - Unmute un utilisateur (admin)
    /kick <user>    - Expulse un utilisateur (admin)
    /ban <user>     - Expulse et bannit un utilisateur (admin)
    /unban <user>   - Unban un utilisateur (admin)
    """
    client_socket.send(commands.encode("utf-8"))

def change_password(client_socket, username):
    """Change le mot de passe de l'utilisateur"""
    client_socket.send(b"Enter new password: ")
    new_password = client_socket.recv(1024).decode("utf-8").strip()
    
    users = load_users()
    users[username] = new_password
    save_users(users)
    log_action(f"{username} changed their password.")
    
    client_socket.send(b"Password changed successfully!\n")

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
    log_action(f"{username} listed all users.")

def mute_user(client_socket, admin, username):
    """Mute un utilisateur"""
    if username not in connected_users:
        client_socket.send(b"User not found or not online.\n")
        return
    if username in muted_users:
        client_socket.send(b"User is already muted.\n")
        return
    muted_users.add(username)
    log_action(f"{admin} muted {username}.")
    client_socket.send(f"{username} has been muted.\n".encode("utf-8"))

def unmute_user(client_socket, admin, username):
    """Unmute un utilisateur"""
    if username not in muted_users:
        client_socket.send(b"User is not muted.\n")
        return
    muted_users.remove(username)
    log_action(f"{admin} unmuted {username}.")
    client_socket.send(f"{username} has been unmuted.\n".encode("utf-8"))

def kick_user(client_socket, admin, username):
    """Kick un utilisateur"""
    for client, uname in clients:
        if uname == username:
            client.send(b"You have been kicked by an admin.\n")
            client.close()
            log_action(f"{admin} kicked {username}.")
            client_socket.send(f"{username} has been kicked.\n".encode("utf-8"))
            return
    client_socket.send(b"User not found or not online.\n")

def ban_user(client_socket, admin, username):
    """Ban un utilisateur"""
    for client, uname in clients:
        if uname == username:
            client.send(b"You have been banned by an admin.\n")
            client.close()
            log_action(f"{admin} banned {username}.")
            client_socket.send(f"{username} has been banned.\n".encode("utf-8"))
            banned_users.add(username)
            clients.remove((client, uname))
            connected_users.discard(username)
            return
    client_socket.send(b"User not found or not online.\n")

def unban_user(client_socket, admin, username):
    """Unban un utilisateur"""
    if username not in banned_users:
        client_socket.send(b"User is not banned.\n")
        return
    banned_users.remove(username)
    log_action(f"{admin} unbanned {username}.")
    client_socket.send(f"{username} has been unbanned.\n".encode("utf-8"))

def whoami(client_socket, username):
    """Affiche le pseudo de l'utilisateur"""
    client_socket.send(f"Your username is {username}\n".encode("utf-8"))

def online(client_socket):
    """Affiche les utilisateurs connectés"""
    online_users = "\n".join(connected_users)
    client_socket.send(f"Online users:\n{online_users}\n".encode("utf-8"))

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
                logout(client_socket, username)
                break
            elif message.lower() == "/changepass":
                change_password(client_socket, username)
            elif message.lower() == "/help":
                send_help(client_socket)
            elif message.lower() == "/deleteaccount":
                if delete_account(client_socket, username):
                    break
            elif message.lower() == "/listusers" and username == "admin":
                list_users(client_socket, username)
            elif message.lower() == "/whoami":
                whoami(client_socket, username)
            elif message.lower() == "/online":
                online(client_socket)
            elif message.startswith("/mute ") and username == "admin":
                target = message.split(" ")[1]
                mute_user(client_socket, username, target)
            elif message.startswith("/unmute ") and username == "admin":
                target = message.split(" ")[1]
                unmute_user(client_socket, username, target)
            elif message.startswith("/kick ") and username == "admin":
                target = message.split(" ")[1]
                kick_user(client_socket, username, target)
            elif message.startswith("/ban ") and username == "admin":
                target = message.split(" ")[1]
                ban_user(client_socket, username, target)
            elif message.startswith("/unban ") and username == "admin":
                target = message.split(" ")[1]
                unban_user(client_socket, username, target)
            elif message.startswith("/"):
                client_socket.send(b"Unknown command. Type /help for a list of commands.\n")
            else:
                if username in muted_users:
                    client_socket.send(b"You are muted and cannot send messages.\n")
                else:
                    log_action(f"{username}: {message}")
                    broadcast_message(f"{username}: {message}", client_socket)

    except Exception as e:
        print(f"Exception: {e}")

    if username:
        logout(client_socket, username)

    log_action(f"{username} logged out.")
    clients.remove((client_socket, username))
    connected_users.discard(username)
    client_socket.close()

def broadcast_message(message, sender_socket):
    """Diffuse un message à tous les clients sauf l'expéditeur"""
    for client, _ in clients:
        if client != sender_socket:
            try:
                client.send(message.encode("utf-8"))
            except:
                client.close()
                clients.remove((client, _))

def start_server():
    """Lance le serveur"""
    log_action("Server started.")
    print("Server started.")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"Listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket, addr)).start()

if __name__ == "__main__":
    start_server()