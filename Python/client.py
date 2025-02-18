import socket
import threading

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
ENCRYPTION_KEY = "SECRETKEY"

def vigenere_encrypt(plain_text, key):
    """Chiffre un texte en clair en utilisant le chiffrement de Vigenère"""
    key = key.upper()
    cipher_text = []
    key_index = 0

    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            if char.isupper():
                cipher_text.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            else:
                cipher_text.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            key_index = (key_index + 1) % len(key)
        else:
            cipher_text.append(char)

    return ''.join(cipher_text)

def vigenere_decrypt(cipher_text, key):
    """Déchiffre un texte chiffré en utilisant le chiffrement de Vigenère"""
    key = key.upper()
    plain_text = []
    key_index = 0

    for char in cipher_text:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('A')
            if char.isupper():
                plain_text.append(chr((ord(char) - ord('A') - shift + 26) % 26 + ord('A')))
            else:
                plain_text.append(chr((ord(char) - ord('a') - shift + 26) % 26 + ord('a')))
            key_index = (key_index + 1) % len(key)
        else:
            plain_text.append(char)

    return ''.join(plain_text)

def receive_messages(client_socket):
    """Reçoit et affiche les messages du serveur"""
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                decrypted_message = vigenere_decrypt(message, ENCRYPTION_KEY)
                print("\n" + decrypted_message)
        except:
            print("[!] Déconnecté du serveur")
            client_socket.close()
            break

def login_or_register(client_socket):
    """Gère la connexion et l'inscription"""
    while True:
        server_msg = client_socket.recv(1024).decode("utf-8")
        decrypted_msg = vigenere_decrypt(server_msg, ENCRYPTION_KEY)
        if "successful" in decrypted_msg:
            print(decrypted_msg)
            return
        print(decrypted_msg, end="")
        client_socket.send(vigenere_encrypt(input(), ENCRYPTION_KEY).encode("utf-8"))

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
                client_socket.send(vigenere_encrypt("/logout", ENCRYPTION_KEY).encode("utf-8"))
                print("[*] Déconnexion en cours... Retour au menu principal.")
                break
            client_socket.send(vigenere_encrypt(message, ENCRYPTION_KEY).encode("utf-8"))

        client_socket.close()
        print("[*] Déconnecté du serveur. Reconnexion au menu...")
        # Retour au menu login/register sans fermer le client

if __name__ == "__main__":
    start_client()