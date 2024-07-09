from tkinter import *
from tkinter import filedialog,messagebox
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

wn = Tk()
wn.title("Secret Notes")
wn.minsize(height=550, width=300)
FONT = ("Verdena", 15, "normal")
def generate_key(password):
    salt = b'\x00' * 16
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_text(text, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())
    return encrypted.decode()

def decrypt_text(text, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(text.encode())
    return decrypted.decode()
def button_clicked():
    title = title_entry.get()
    secret_text = text.get("1.0", END)
    master_key = key_entry.get()

    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text files", "*.txt"),
                                                        ("All files", "*.*")])

    if len(title) == 0 or len(secret_text) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        key = generate_key(master_key)
        encrypted_text = encrypt_text(secret_text, key)
        try:
            with open(file_path, "a") as file:
                file.write(f"\n{title}\n{encrypted_text}")
            status_label.config(text="The text was successfully encrypted and saved.", font=FONT)
        except FileNotFoundError:
            with open(file_path, "w") as file:
                file.write(f"\n{title}\n{encrypted_text}")
        finally:
            title_entry.delete(0, END)
            key_entry.delete(0, END)
            text.delete("1.0", END)



def Decrypt_clicked():
    master_key = key_entry.get()
    message_encrypted = text.get("1.0", END)

    if len(message_encrypted) == 0 or len(master_key) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            key = generate_key(master_key)
            decrypted_text = decrypt_text(message_encrypted, key)
            text.delete("1.0", END)
            text.insert("1.0", decrypted_text)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")
      

photo = PhotoImage(file="secret.png")
photo_label = Label(image=photo)
photo_label.pack()

title_label = Label(text="Enter your title", font=FONT)
title_label.pack()

title_entry = Entry(width=20)
title_entry.pack()

text_label = Label(text="Enter your secret", font=FONT)
text_label.pack()

text = Text(width=30, height=10)
text.pack()

key_label = Label(text="Enter master key", font=FONT)
key_label.pack()

key_entry = Entry(width=25)
key_entry.pack()

save_Encrypt = Button(text="Save & Encrypt", command=button_clicked, font=FONT)
save_Encrypt.config(pady=5, padx=10)
save_Encrypt.pack()

decrypt = Button(text="Decrypt", command=Decrypt_clicked, font=FONT)
decrypt.config(pady=3, padx=5)
decrypt.pack()

status_label = Label(text="", font=FONT)
status_label.pack()


wn.mainloop()


