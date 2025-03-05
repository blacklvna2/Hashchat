import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

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
    global waiting_for_login
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                decrypted_message = rsa_decrypt(message, client_private_key)

                if "login" in decrypted_message.lower() or "register" in decrypted_message.lower():
                    display_message(f"[SERVEUR] {decrypted_message}")
                    waiting_for_login = True
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
    global waiting_for_login
    message = message_entry.get()
    
    if message:
        encrypted_message = rsa_encrypt(message, server_public_key)
        client_socket.send(encrypted_message.encode("utf-8"))
        if not waiting_for_login:
            display_message(f"Moi: {message}")

        message_entry.delete(0, tk.END)

def display_message(message):
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, message + "\n")
    chat_display.config(state=tk.DISABLED)
    chat_display.yview(tk.END)

def start_client():
    global client_socket, waiting_for_login, client_private_key
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    
    # Générer une paire de clés RSA pour le client
    client_key = RSA.generate(2048)
    client_private_key = client_key
    client_public_key = client_key.publickey().export_key()

    # Envoyer la clé publique du client au serveur
    client_socket.send(client_public_key)
    
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
        pass

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