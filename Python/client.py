import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
ENCRYPTION_KEY = "SECRETKEY"

def vigenere_encrypt(plain_text, key):
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

def receive_messages():
    global waiting_for_login
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                decrypted_message = vigenere_decrypt(message, ENCRYPTION_KEY)

                # Si le serveur demande login ou register, on attend une réponse utilisateur
                if "login" in decrypted_message.lower() or "register" in decrypted_message.lower():
                    display_message(f"[SERVEUR] {decrypted_message}")
                    waiting_for_login = True
                elif decrypted_message.strip() == "/logout":
                    logout()
                    break
                else:
                    display_message(decrypted_message)
        except:
            messagebox.showerror("Erreur", "Déconnecté du serveur")
            client_socket.close()
            break

def send_message(event=None):
    global waiting_for_login
    message = message_entry.get()
    
    if message:
        if waiting_for_login:  # Si on attend une réponse de connexion/enregistrement
            client_socket.send(vigenere_encrypt(message, ENCRYPTION_KEY).encode("utf-8"))
            waiting_for_login = False  # On repasse en mode chat normal
        else:
            client_socket.send(vigenere_encrypt(message, ENCRYPTION_KEY).encode("utf-8"))
            display_message(f"Moi: {message}")

        message_entry.delete(0, tk.END)

def display_message(message):
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, message + "\n")
    chat_display.config(state=tk.DISABLED)
    chat_display.yview(tk.END)

def start_client():
    global client_socket, waiting_for_login
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    
    waiting_for_login = False  # On commence en mode chat normal
    threading.Thread(target=receive_messages, daemon=True).start()

def logout():
    messagebox.showinfo("Déconnexion", "Vous êtes déconnecté.")
    client_socket.close()

def main():
    global root, chat_display, message_entry
    root = tk.Tk()
    root.title("Chat Client")
    root.geometry("600x750")

    chat_display = scrolledtext.ScrolledText(root, state=tk.DISABLED, wrap=tk.WORD)
    chat_display.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

    message_entry = tk.Entry(root, width=50)
    message_entry.pack(pady=5, padx=10, side=tk.LEFT, fill=tk.X, expand=True)
    message_entry.bind("<Return>", send_message)

    send_button = tk.Button(root, text="Envoyer", command=send_message)
    send_button.pack(pady=5, padx=10, side=tk.RIGHT)

    logout_button = tk.Button(root, text="Logout", command=logout)
    logout_button.pack(pady=5, padx=10, side=tk.BOTTOM)

    threading.Thread(target=start_client, daemon=True).start()

    root.mainloop()

if __name__ == "__main__":
    main()
