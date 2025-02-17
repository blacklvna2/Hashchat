import socket
import threading

# Paramètres du serveur
HOST = '0.0.0.0'  # Écoute sur toutes les interfaces réseau
PORT = 12345       # Port d'écoute

# Liste pour stocker les clients connectés
clients = []

def handle_client(client_socket, addr):
    """Gère un client connecté"""
    print(f"[+] Nouvelle connexion de {addr}")
    clients.append(client_socket)
    
    try:
        while True:
            message = client_socket.recv(1024).decode("utf-8")
            if not message:
                break
            print(f"[{addr}] {message}")
            
            # Relaye le message à tous les autres clients
            for client in clients:
                if client != client_socket:
                    try:
                        client.send(f"[{addr}] {message}".encode("utf-8"))
                    except:
                        clients.remove(client)
    except:
        pass

    print(f"[-] Déconnexion de {addr}")
    clients.remove(client_socket)
    client_socket.close()

def start_server():
    """Lance le serveur"""
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
