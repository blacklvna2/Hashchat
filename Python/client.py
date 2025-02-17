import socket
import threading

SERVER_IP = "10.2.111.56"
SERVER_PORT = 12345

def receive_messages(client_socket):
    """Reçoit et affiche les messages du serveur"""
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                print("\n" + message)
        except:
            print("[!] Déconnecté du serveur")
            client_socket.close()
            break

def login_or_register(client_socket):
    """Gère la connexion et l'inscription"""
    while True:
        server_msg = client_socket.recv(1024).decode("utf-8")
        if "successful" in server_msg:
            print(server_msg)
            return
        print(server_msg, end="")
        client_socket.send(input().encode("utf-8"))

def start_client():
    """Lance un client"""
    while True:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print("[*] Connecté au serveur de chat")

        login_or_register(client_socket)

        # Thread pour écouter les messages entrants
        thread = threading.Thread(target=receive_messages, args=(client_socket,))
        thread.start()

        while True:
            message = input("")
            if message.lower() == "/logout":
                client_socket.send(b"/logout")
                print("[*] Déconnexion en cours... Retour au menu principal.")
                break
            client_socket.send(message.encode("utf-8"))

        client_socket.close()
        print("[*] Déconnecté du serveur. Reconnexion au menu...")
        # Retour au menu login/register sans fermer le client

if __name__ == "__main__":
    start_client()
