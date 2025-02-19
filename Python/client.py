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
    while True:
        try:
            message = client_socket.recv(1024).decode("utf-8")
            if message:
                decrypted_message = vigenere_decrypt(message, ENCRYPTION_KEY)
                display_message(f"Serveur: {decrypted_message}")
        except:
            messagebox.showerror("Erreur", "Déconnecté du serveur")
            client_socket.close()
            break

def send_message():
    message = message_entry.get()
    if message:
        client_socket.send(vigenere_encrypt(message, ENCRYPTION_KEY).encode("utf-8"))
        display_message(f"Moi: {message}")
        message_entry.delete(0, tk.END)

def display_message(message):
    chat_display.config(state=tk.NORMAL)
    chat_display.insert(tk.END, message + "\n")
    chat_display.config(state=tk.DISABLED)
    chat_display.yview(tk.END)

def login_or_register():
    while True:
        server_msg = client_socket.recv(1024).decode("utf-8")
        decrypted_msg = vigenere_decrypt(server_msg, ENCRYPTION_KEY)
        if "successful" in decrypted_msg.lower():
            messagebox.showinfo("Succès", decrypted_msg)
            break
        response = simple_input_popup("Connexion", decrypted_msg)
        client_socket.send(vigenere_encrypt(response, ENCRYPTION_KEY).encode("utf-8"))

def simple_input_popup(title, prompt):
    user_input = tk.StringVar()
    popup = tk.Toplevel()
    popup.title(title)
    
    tk.Label(popup, text=prompt).pack()
    entry = tk.Entry(popup, textvariable=user_input)
    entry.pack()
    entry.focus()
    
    def submit():
        popup.destroy()
    
    tk.Button(popup, text="OK", command=submit).pack()
    popup.grab_set()
    popup.wait_window()
    
    return user_input.get()

def start_client():
    global client_socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    login_or_register()
    threading.Thread(target=receive_messages, daemon=True).start()

def on_closing():
    client_socket.close()
    root.destroy()

# Interface Tkinter
root = tk.Tk()
root.title("Chat Client")
root.geometry("400x500")

chat_display = scrolledtext.ScrolledText(root, state=tk.DISABLED, wrap=tk.WORD)
chat_display.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

message_entry = tk.Entry(root, width=50)
message_entry.pack(pady=5, padx=10, side=tk.LEFT, fill=tk.X, expand=True)

send_button = tk.Button(root, text="Envoyer", command=send_message)
send_button.pack(pady=5, padx=10, side=tk.RIGHT)

# Démarrer le client en arrière-plan
threading.Thread(target=start_client, daemon=True).start()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()