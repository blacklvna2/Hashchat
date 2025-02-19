import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
ENCRYPTION_KEY = b'Sixteen byte key'  # Clé AES doit être de 16, 24 ou 32 bytes

def aes_encrypt(plain_text, key):
    """Chiffre un texte en clair en utilisant AES"""
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plain_text.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def aes_decrypt(cipher_text, key):
    """Déchiffre un texte chiffré en utilisant AES"""
    iv = base64.b64decode(cipher_text[:24])
    ct = base64.b64decode(cipher_text[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def receive_messages():
    global waiting_for_login
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                decrypted_message = aes_decrypt(message, ENCRYPTION_KEY)

                # Si le serveur demande login ou register, on attend une réponse utilisateur
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
        if waiting_for_login:  # Si on attend une réponse de connexion/enregistrement
            client_socket.send(aes_encrypt(message, ENCRYPTION_KEY).encode("utf-8"))
            waiting_for_login = False  # On repasse en mode chat normal
        else:
            client_socket.send(aes_encrypt(message, ENCRYPTION_KEY).encode("utf-8"))
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
    messagebox.showinfo("Déconnexion", "Vous êtes déconnecté. Fermeture dans 2 secondes...")
    
    try:
        client_socket.send(aes_encrypt("/logout", ENCRYPTION_KEY).encode("utf-8"))
        client_socket.close()
        root.after(2000, root.destroy)
    except:
        pass  # Si la connexion est déjà fermée, on ignore l'erreur



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