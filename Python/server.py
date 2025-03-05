import socket
import threading
import os
import datetime
from Crypto.Util.Padding import pad, unpad
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

# Paramètres du serveur
HOST = '127.0.0.1'
PORT = 12345
clients = []  # Liste des (socket, username, public_key)
connected_users = set()  # Liste des utilisateurs connectés
muted_users = set()  # Liste des utilisateurs mutés
banned_users = set()  # Liste des utilisateurs bannis
user_data_file = "users.json"

# Générer une paire de clés RSA pour le serveur
server_key = RSA.generate(2048)
server_public_key = server_key.publickey().export_key()
server_private_key = server_key.export_key()

# Sauvegarder la clé publique du serveur dans un fichier
with open("server_public_key.pem", "wb") as f:
    f.write(server_public_key)

# Sauvegarder la clé privée du serveur dans un fichier (optionnel)
with open("server_private_key.pem", "wb") as f:
    f.write(server_private_key)

# Création du dossier logs
if not os.path.exists("logs"):
    os.makedirs("logs")

# Création d'un fichier log unique pour chaque session
log_filename = f"logs/server_log_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"

def log_action(action):
    """Enregistre une action dans le fichier log"""
    with open(log_filename, "a") as log_file:
        log_file.write(f"{datetime.datetime.now()} - {action}\n")

def load_users():
    """Charge les utilisateurs depuis le fichier JSON"""
    with open(user_data_file, "r") as f:
        return json.load(f)

def save_users(users):
    """Enregistre les utilisateurs dans le fichier JSON"""
    with open(user_data_file, "w") as f:
        json.dump(users, f)

def rsa_encrypt(plain_text, public_key):
    """Chiffre un texte en clair en utilisant RSA"""
    recipient_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted_message = cipher_rsa.encrypt(plain_text.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

def rsa_decrypt(cipher_text, private_key):
    """Déchiffre un texte chiffré en utilisant RSA"""
    private_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(base64.b64decode(cipher_text))
    return decrypted_message.decode('utf-8')

def register(client_socket):
    """Gère l'inscription"""
    client_socket.send(rsa_encrypt("Enter username: ", server_public_key).encode("utf-8"))
    username = rsa_decrypt(client_socket.recv(1024).decode("utf-8"), server_private_key).strip()
    
    client_socket.send(rsa_encrypt("Enter password: ", server_public_key).encode("utf-8"))
    password = rsa_decrypt(client_socket.recv(1024).decode("utf-8"), server_private_key).strip()

    users = load_users()
    if username in users:
        client_socket.send(rsa_encrypt("Username already exists.\n", server_public_key).encode("utf-8"))
        return None

    users[username] = password
    save_users(users)
    log_action(f"New user registered: {username}")
    client_socket.send(rsa_encrypt("Registration successful!\n", server_public_key).encode("utf-8"))
    return None

def login(client_socket):
    """Gère la connexion"""
    client_socket.send(rsa_encrypt("Enter username: ", server_public_key).encode("utf-8"))
    username = rsa_decrypt(client_socket.recv(1024).decode("utf-8"), server_private_key).strip()
    
    if username in banned_users:
        client_socket.send(rsa_encrypt("You are banned from this server.\n", server_public_key).encode("utf-8"))
        return None

    client_socket.send(rsa_encrypt("Enter password: ", server_public_key).encode("utf-8"))
    password = rsa_decrypt(client_socket.recv(1024).decode("utf-8"), server_private_key).strip()

    users = load_users()
    if username not in users or users[username] != password:
        client_socket.send(rsa_encrypt("Invalid username or password.\n", server_public_key).encode("utf-8"))
        return None

    if users.get(username) == password:
        client_socket.send(aes_encrypt("Login successful!", ENCRYPTION_KEY).encode("utf-8"))
        client_socket.send(aes_encrypt("CONNECTED", ENCRYPTION_KEY).encode("utf-8"))
        connected_users.add(username)
        log_action(f"{username} logged in.")
        return username
    else:
        client_socket.send(aes_encrypt("Invalid credentials!\n", ENCRYPTION_KEY).encode("utf-8"))
    if username in connected_users:
        client_socket.send(rsa_encrypt("User already logged in.\n", server_public_key).encode("utf-8"))
        return None

    log_action(f"User logged in: {username}")
    client_socket.send(rsa_encrypt("Login successful!\n", server_public_key).encode("utf-8"))
    return username

def logout(client_socket, username):
    """Gère la déconnexion"""
    log_action(f"User logged out: {username}")
    client_socket.send(rsa_encrypt("Logout successful!\n", server_public_key).encode("utf-8"))

def send_help(client_socket):
    """Envoie la liste des commandes disponibles"""
    help_message = """
    Available commands:
    /help - Show this help message
    /logout - Logout from the server
    /changepassword - Change your password
    /deleteaccount - Delete your account
    /listusers - List all users
    /mute <username> - Mute a user (admin only)
    /unmute <username> - Unmute a user (admin only)
    /kick <username> - Kick a user (admin only)
    /ban <username> - Ban a user (admin only)
    /unban <username> - Unban a user (admin only)
    /whoami - Show your username
    /online - Show online users
    """
    client_socket.send(rsa_encrypt(help_message, server_public_key).encode("utf-8"))

def change_password(client_socket, username):
    """Permet de changer le mot de passe"""
    client_socket.send(rsa_encrypt("Enter new password: ", server_public_key).encode("utf-8"))
    new_password = rsa_decrypt(client_socket.recv(1024).decode("utf-8"), server_private_key).strip()

    users = load_users()
    users[username] = new_password
    save_users(users)
    log_action(f"User changed password: {username}")
    client_socket.send(rsa_encrypt("Password changed successfully!\n", server_public_key).encode("utf-8"))

def delete_account(client_socket, username):
    """Permet de supprimer un compte utilisateur"""
    users = load_users()
    if username in users:
        del users[username]
        save_users(users)
        log_action(f"User deleted account: {username}")
        client_socket.send(rsa_encrypt("Account deleted successfully!\n", server_public_key).encode("utf-8"))
    else:
        client_socket.send(rsa_encrypt("Account not found.\n", server_public_key).encode("utf-8"))

def list_users(client_socket, username):
    """Liste tous les utilisateurs"""
    users = load_users()
    user_list = "\n".join(users.keys())
    client_socket.send(rsa_encrypt(f"Users:\n{user_list}\n", server_public_key).encode("utf-8"))

def mute_user(client_socket, admin, username):
    """Permet de muter un utilisateur (admin seulement)"""
    if admin != "admin":
        client_socket.send(rsa_encrypt("Permission denied.\n", server_public_key).encode("utf-8"))
        return

    muted_users.add(username)
    log_action(f"User muted: {username}")
    client_socket.send(rsa_encrypt(f"User {username} muted.\n", server_public_key).encode("utf-8"))

def unmute_user(client_socket, admin, username):
    """Permet de démuter un utilisateur (admin seulement)"""
    if admin != "admin":
        client_socket.send(rsa_encrypt("Permission denied.\n", server_public_key).encode("utf-8"))
        return

    muted_users.discard(username)
    log_action(f"User unmuted: {username}")
    client_socket.send(rsa_encrypt(f"User {username} unmuted.\n", server_public_key).encode("utf-8"))

def kick_user(client_socket, admin, username):
    """Permet de kicker un utilisateur (admin seulement)"""
    if admin != "admin":
        client_socket.send(rsa_encrypt("Permission denied.\n", server_public_key).encode("utf-8"))
        return

    for client in clients:
        if client[1] == username:
            client[0].send(rsa_encrypt("You have been kicked by an admin.\n", server_public_key).encode("utf-8"))
            client[0].close()
            clients.remove(client)
            log_action(f"User kicked: {username}")
            break

def ban_user(client_socket, admin, username):
    """Permet de bannir un utilisateur (admin seulement)"""
    if admin != "admin":
        client_socket.send(rsa_encrypt("Permission denied.\n", server_public_key).encode("utf-8"))
        return

    banned_users.add(username)
    log_action(f"User banned: {username}")
    client_socket.send(rsa_encrypt(f"User {username} banned.\n", server_public_key).encode("utf-8"))

def unban_user(client_socket, admin, username):
    """Permet de débannir un utilisateur (admin seulement)"""
    if admin != "admin":
        client_socket.send(rsa_encrypt("Permission denied.\n", server_public_key).encode("utf-8"))
        return

    banned_users.discard(username)
    log_action(f"User unbanned: {username}")
    client_socket.send(rsa_encrypt(f"User {username} unbanned.\n", server_public_key).encode("utf-8"))

def whoami(client_socket, username):
    """Affiche le nom d'utilisateur"""
    client_socket.send(rsa_encrypt(f"You are {username}\n", server_public_key).encode("utf-8"))

def online(client_socket):
    """Affiche les utilisateurs en ligne"""
    online_users = "\n".join([client[1] for client in clients])
    client_socket.send(rsa_encrypt(f"Online users:\n{online_users}\n", server_public_key).encode("utf-8"))

def handle_client(client_socket, addr):
    """Gère les interactions avec un client"""
    print(f"[+] New connection from {addr}")
    client_socket.send(rsa_encrypt("Welcome to the server!\n", server_public_key).encode("utf-8"))

    # Recevoir la clé publique du client
    client_public_key = client_socket.recv(1024)
    clients.append((client_socket, None, client_public_key))

    while True:
        try:
            message = rsa_decrypt(client_socket.recv(1024).decode("utf-8"), server_private_key)
            if message.startswith("/"):
                command, *args = message.split()
                if command == "/register":
                    register(client_socket)
                elif command == "/login":
                    username = login(client_socket)
                    if username:
                        for i, client in enumerate(clients):
                            if client[0] == client_socket:
                                clients[i] = (client_socket, username, client_public_key)
                                break
                elif command == "/logout":
                    username = next((client[1] for client in clients if client[0] == client_socket), None)
                    if username:
                        logout(client_socket, username)
                        clients.remove((client_socket, username, client_public_key))
                        break
                elif command == "/help":
                    send_help(client_socket)
                elif command == "/changepassword":
                    username = next((client[1] for client in clients if client[0] == client_socket), None)
                    if username:
                        change_password(client_socket, username)
                elif command == "/deleteaccount":
                    username = next((client[1] for client in clients if client[0] == client_socket), None)
                    if username:
                        delete_account(client_socket, username)
                        clients.remove((client_socket, username, client_public_key))
                        break
                elif command == "/listusers":
                    username = next((client[1] for client in clients if client[0] == client_socket), None)
                    if username:
                        list_users(client_socket, username)
                elif command == "/mute":
                    admin = next((client[1] for client in clients if client[0] == client_socket), None)
                    if admin:
                        mute_user(client_socket, admin, args[0])
                elif command == "/unmute":
                    admin = next((client[1] for client in clients if client[0] == client_socket), None)
                    if admin:
                        unmute_user(client_socket, admin, args[0])
                elif command == "/kick":
                    admin = next((client[1] for client in clients if client[0] == client_socket), None)
                    if admin:
                        kick_user(client_socket, admin, args[0])
                elif command == "/ban":
                    admin = next((client[1] for client in clients if client[0] == client_socket), None)
                    if admin:
                        ban_user(client_socket, admin, args[0])
                elif command == "/unban":
                    admin = next((client[1] for client in clients if client[0] == client_socket), None)
                    if admin:
                        unban_user(client_socket, admin, args[0])
                elif command == "/whoami":
                    username = next((client[1] for client in clients if client[0] == client_socket), None)
                    if username:
                        whoami(client_socket, username)
                elif command == "/online":
                    online(client_socket)
                else:
                    client_socket.send(rsa_encrypt("Unknown command.\n", server_public_key).encode("utf-8"))
            else:
                broadcast_message(message, client_socket)
        except Exception as e:
            print(f"[-] Error: {e}")
            break

    client_socket.close()

def broadcast_message(message, sender_socket):
    """Diffuse un message à tous les clients"""
    for client_socket, username, public_key in clients:
        if client_socket != sender_socket:
            try:
                encrypted_message = rsa_encrypt(message, public_key)
                client_socket.send(encrypted_message.encode("utf-8"))
            except:
                client_socket.close()
                clients.remove((client_socket, username, public_key))

def start_server():
    """Démarre le serveur"""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client_socket, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()