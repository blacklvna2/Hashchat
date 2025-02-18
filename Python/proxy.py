import socket
import threading

# Configuration du MITM Proxy
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 9999  # Port du proxy
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 12345  # Port du vrai serveur

def handle_client(client_socket):
    """Relaye les données entre le client et le serveur tout en les affichant."""
    
    # Connexion au vrai serveur
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect((SERVER_HOST, SERVER_PORT))

    def forward_data(source, destination, direction):
        """Transfère les données et les affiche"""
        while True:
            try:
                data = source.recv(1024)
                if not data:
                    break
                print(f"[{direction}] {data.decode(errors='ignore')}")
                destination.sendall(data)
            except:
                break

    # Création de deux threads pour gérer les communications bidirectionnelles
    threading.Thread(target=forward_data, args=(client_socket, server_socket, "CLIENT → SERVEUR"), daemon=True).start()
    threading.Thread(target=forward_data, args=(server_socket, client_socket, "SERVEUR → CLIENT"), daemon=True).start()

if __name__ == "__main__":
    proxy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy.bind((PROXY_HOST, PROXY_PORT))
    proxy.listen(5)
    print(f"[*] Proxy MITM en écoute sur {PROXY_HOST}:{PROXY_PORT}")

    while True:
        client_socket, addr = proxy.accept()
        print(f"[+] Connexion interceptée de {addr}")
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()
