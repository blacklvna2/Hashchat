
import socket
import threading

# Paramètres du serveur
SERVER_IP = "127.0.0.1"  # À changer si le serveur est sur une autre machine
SERVER_PORT = 12345

def receive_messages(client_socket):
    """Reçoit les messages du serveur et les affiche"""
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                print("\n" + message)
        except:
            print("[!] Déconnecté du serveur")
            client_socket.close()
            break

def start_client():
    """Lance un client"""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print("[*] Connecté au serveur de chat")

    # Thread pour écouter les messages entrants
    thread = threading.Thread(target=receive_messages, args=(client_socket,))
    thread.start()

    while True:
        message = input("")
        if message.lower() == "exit":
            break
        client_socket.send(message.encode("utf-8"))

    client_socket.close()

if __name__ == "__main__":
    start_client()
