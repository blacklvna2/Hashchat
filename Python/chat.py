import tkinter as tk
from tkinter import scrolledtext

class MessagerieInterface:
    def __init__(self, root):
        self.root = root
        self.root.title("Messagerie")

        self.chat_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.chat_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.message_entry = tk.Entry(root, width=100)
        self.message_entry.pack(padx=10, pady=10, side=tk.LEFT, fill=tk.X, expand=True)
        self.message_entry.bind("<Return>", self.send_message)

        self.send_button = tk.Button(root, text="Envoyer", command=self.send_message)
        self.send_button.pack(padx=10, pady=10, side=tk.RIGHT)

    def send_message(self, event=None):
        message = self.message_entry.get()
        if message:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, f"Vous: {message}\n")
            self.chat_display.config(state='disabled')
            self.message_entry.delete(0, tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = MessagerieInterface(root)
    root.mainloop()