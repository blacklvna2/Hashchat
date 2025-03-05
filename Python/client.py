import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import os
import signal

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999

# Charger la clé publique du serveur
with open("server_public_key.pem", "rb") as f:
    server_public_key = RSA.import_key(f.read())

def rsa_encrypt(plain_text, public_key):
    """Chiffre un texte en clair en utilisant RSA"""
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(plain_text.encode('utf-8'))
    return base64.b64encode(encrypted_message).decode('utf-8')

def rsa_decrypt(cipher_text, private_key):
    """Déchiffre un texte chiffré en utilisant RSA"""
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(base64.b64decode(cipher_text))
    return decrypted_message.decode('utf-8')

def receive_messages():
    global waiting_for_login, is_logged_in
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                decrypted_message = rsa_decrypt(message, client_private_key)

                if "login" in decrypted_message.lower() or "register" in decrypted_message.lower():
                    display_message(f"[SERVEUR] {decrypted_message}")
                    waiting_for_login = True
                elif decrypted_message.strip() == "CONNECTED":
                    is_logged_in = True
                    waiting_for_login = False
                    display_message(f"[SERVEUR] {decrypted_message}")
                elif decrypted_message.strip() == "/logout":
                    logout()
                    break
                elif decrypted_message.strip() == "You have been kicked by an admin.":
                    display_message(f'{decrypted_message}, Fermeture de la fenetre dans 2 secondes')
                    root.after(2000, root.destroy)
                    break
                elif decrypted_message.strip() == "You have been banned by an admin.":
                    display_message(f'{decrypted_message}, Fermeture de la fenetre dans 2 secondes')
                    root.after(2000, root.destroy)
                    break
                else:
                    display_message(decrypted_message)
        except Exception as e:
            messagebox.showerror("Erreur", f"Déconnecté du serveur: {e}")
            client_socket.close()
            break

def send_message(event=None):
    global waiting_for_login, is_logged_in
    message = message_entry.get()
    
    if message:
        encrypted_message = rsa_encrypt(message, server_public_key)
        if waiting_for_login:  # Si on attend une réponse de connexion/enregistrement
            client_socket.send(encrypted_message.encode("utf-8"))
        elif is_logged_in:  # Si l'utilisateur est connecté
            client_socket.send(encrypted_message.encode("utf-8"))
            display_message(f"Moi: {message}")

        message_entry.delete(0, tk.END)

def display_message(message):
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, message + "\n")
    chat_display.config(state=tk.DISABLED)
    chat_display.yview(tk.END)

def start_client():
    global client_socket, waiting_for_login, client_private_key, is_logged_in
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    
    # Générer une paire de clés RSA pour le client
    client_key = RSA.generate(2048)
    client_private_key = client_key
    client_public_key = client_key.publickey().export_key()

    # Envoyer la clé publique du client au serveur
    client_socket.send(client_public_key)
    
    is_logged_in = False
    waiting_for_login = False
    threading.Thread(target=receive_messages, daemon=True).start()

def logout():
    messagebox.showinfo("Déconnexion", "Vous êtes déconnecté. Fermeture dans 2 secondes...")
    
    try:
        encrypted_message = rsa_encrypt("/logout", server_public_key)
        client_socket.send(encrypted_message.encode("utf-8"))
        client_socket.close()
        root.after(2000, root.destroy)
    except:
        pass  # Si la connexion est déjà fermée, on ignore l'erreur

def on_closing():
    logout()
    os.kill(os.getpid(), signal.SIGTERM)

def main():
    global root, chat_display, message_entry
    root = tk.Tk()
    root.title("Chat Client")
    root.geometry("500x500")
    root.minsize(500, 300)  # Définir la taille minimale de la fenêtre

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    root.grid_columnconfigure(2, weight=1)

    chat_display = scrolledtext.ScrolledText(root, state=tk.DISABLED, wrap=tk.WORD)
    chat_display.grid(row=0, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

    message_entry = tk.Entry(root, width=40)
    message_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
    message_entry.bind("<Return>", send_message)

    send_button = tk.Button(root, text="Envoyer", command=send_message)
    send_button.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

    logout_button = tk.Button(root, text="Logout", command=logout)
    logout_button.grid(row=1, column=2, padx=10, pady=5, sticky="ew")

    threading.Thread(target=start_client, daemon=True).start()

    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()