import base64
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from tkinter.simpledialog import askstring
 
class CreditCardEncryptionGUI:
 
    def _init_(self):
        self.root = Tk()
        self.root.title("Credit Card Encryption")
        self.root.configure(bg="black")  # Set the background color to black
 
        self.credit_card_label = Label(self.root, text="Credit Card Number:", bg="black", fg="white")
        self.credit_card_label.grid(row=0, column=0, padx=5, pady=5)
        self.credit_card_entry = Entry(self.root)
        self.credit_card_entry.grid(row=0, column=1, padx=5, pady=5)
 
        self.passphrase_label = Label(self.root, text="Passphrase:", bg="black", fg="white")
        self.passphrase_label.grid(row=1, column=0, padx=5, pady=5)
        self.passphrase_entry = Entry(self.root)
        self.passphrase_entry.grid(row=1, column=1, padx=5, pady=5)
 
        self.encrypt_button = Button(self.root, text="Encrypt", command=self.encrypt_credit_card, bg="black", fg="white")
        self.encrypt_button.grid(row=2, column=0, padx=5, pady=5)
 
        self.decrypt_button = Button(self.root, text="Decrypt", command=self.decrypt_credit_card, bg="black", fg="white")
        self.decrypt_button.grid(row=2, column=1, padx=5, pady=5)
 
        self.output_text = Text(self.root, width=30, height=10, bg="black", fg="white")
        self.output_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)
 
    def encrypt_credit_card(self):
        credit_card_number = self.credit_card_entry.get()
        passphrase = self.passphrase_entry.get()
 
        try:
            backend = default_backend()
            salt = os.urandom(16)
            key = self.derive_key(passphrase, salt)
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(credit_card_number.encode('utf-8')) + padder.finalize()
            encrypted_credit_card = encryptor.update(padded_data) + encryptor.finalize()
            combined = salt + iv + encrypted_credit_card
            encrypted_credit_card = base64.b64encode(combined).decode('utf-8')
            self.output_text.delete(1.0, END)
            self.output_text.insert(END, "Encrypted Credit Card: " + encrypted_credit_card)
 
            # Ask the user if they want to save the encrypted credit card to a file
            save_file = messagebox.askyesno("Save File", "Do you want to save the encrypted credit card to a file?")
            if save_file:
                self.save_encrypted_credit_card(encrypted_credit_card)
 
        except Exception as e:
            self.output_text.delete(1.0, END)
            self.output_text.insert(END, "Encryption failed. Error: " + str(e))
 
    def decrypt_credit_card(self):
        # Ask the user for the input method: Manual entry or file selection
        answer = messagebox.askyesno("Input Method", "Do you want to enter the encrypted credit card manually?")
 
        if answer:
            encrypted_credit_card = askstring("Enter Encrypted Text", "Enter the encrypted credit card number:")
            if not encrypted_credit_card:
                return
        else:
            file_path = filedialog.askopenfilename(title="Select Encrypted Credit Card File",
                                                   filetypes=[("Text Files", "*.txt")])
            if file_path:
                with open(file_path, 'r') as file:
                    encrypted_credit_card = file.read()
            else:
                return
 
        passphrase = self.passphrase_entry.get()
 
        try:
            combined = base64.b64decode(encrypted_credit_card)
            salt = combined[:16]
            iv = combined[16:32]
            encrypted_credit_card = combined[32:]
            key = self.derive_key(passphrase, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            decrypted_credit_card = decryptor.update(encrypted_credit_card) + decryptor.finalize()
            unpadded_data = unpadder.update(decrypted_credit_card) + unpadder.finalize()
            decrypted_credit_card = unpadded_data.decode('utf-8')
            self.output_text.delete(1.0, END)
            self.output_text.insert(END, "Decrypted Credit Card: " + decrypted_credit_card)
        except Exception as e:
            self.output_text.delete(1.0, END)
            self.output_text.insert(END, "Decryption failed. Error: " + str(e))
 
    def derive_key(self, passphrase, salt):
        return hashlib.pbkdf2_hmac('sha256', passphrase.encode('utf-8'), salt, 10000, 32)
 
    def save_encrypted_credit_card(self, encrypted_credit_card):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                                 filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(encrypted_credit_card)
            messagebox.showinfo("Save Successful", "Encrypted credit card saved successfully.")
        else:
            messagebox.showinfo("Save Cancelled", "File save operation cancelled.")
 
    def run(self):
        self.root.mainloop()
 
 
if _name_ == '_main_':
    gui = CreditCardEncryptionGUI()
    gui.run()