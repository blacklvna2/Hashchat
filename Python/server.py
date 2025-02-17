import socket
import threading

"""
    Ce script implémente un serveur de chat multi-thread simple en utilisant les bibliothèques socket et threading de Python.
    Fonctions:
        handle_client(client_socket):
            Gère la communication avec un client connecté. Reçoit les messages du client et les diffuse aux autres clients.
            Si le client se déconnecte, le retire de la liste des clients actifs.
        broadcast(message, client_socket):
            Envoie un message à tous les clients connectés sauf l'expéditeur.
        remove(client_socket):
            Retire un client de la liste des clients actifs.
        start_server():
            Démarre le serveur, écoute les connexions entrantes et crée un nouveau thread pour gérer chaque client connecté.
    Variables Globales:
        clients (list):
            Une liste pour suivre toutes les sockets des clients connectés.
    Utilisation:
        Exécutez ce script pour démarrer le serveur de chat. Le serveur écoute sur toutes les adresses IP disponibles (127.0.0.1) et le port 5555.
    """

def handle_client(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(f"Received: {message}")
                broadcast(message, client_socket)
            else:
                remove(client_socket)
                break
        except:
            continue

def broadcast(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(message.encode('utf-8'))
            except:
                remove(client)

def remove(client_socket):
    if client_socket in clients:
        clients.remove(client_socket)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 5555))
    server.listen(5)
    print("Server started on port 5555")

    while True:
        client_socket, addr = server.accept()
        clients.append(client_socket)
        print(f"Connection from {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

clients = []

if __name__ == "__main__":
    start_server()