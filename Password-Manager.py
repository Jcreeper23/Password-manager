import customtkinter as ctk
from tkinter import messagebox
import json
import os
import base64
from cryptography.fernet import Fernet
import secrets
import string
import pyperclip

import sys
import traceback

def log_exception(exc_type, exc_value, exc_traceback):
    with open("error_log.txt", "w") as f:
        traceback.print_exception(exc_type, exc_value, exc_traceback, file=f)

sys.excepthook = log_exception

# === Config ===
DATA_FILE = "passwords.enc"
ctk.set_appearance_mode("System")  # Light, Dark, System
ctk.set_default_color_theme("blue")  # Options: blue, green, dark-blue


# === Helper Functions ===

def generate_key(master_password: str) -> bytes:
    """Derives a Fernet key from the master password"""
    padded_password = master_password.ljust(32, "0").encode("utf-8")
    return base64.urlsafe_b64encode(padded_password)


def encrypt_data(data: dict, key: bytes) -> bytes:
    """Encrypt data dictionary with Fernet"""
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode())


def decrypt_data(encrypted_data: bytes, key: bytes) -> dict:
    """Decrypt data with Fernet"""
    try:
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_data)
        return json.loads(decrypted.decode())
    except Exception:
        return None


def load_data(file_path: str, key: bytes) -> dict:
    if os.path.exists(file_path):
        with open(file_path, "rb") as file:
            encrypted_data = file.read()
            return decrypt_data(encrypted_data, key)
    return {}


def save_data(file_path: str, data: dict, key: bytes):
    encrypted = encrypt_data(data, key)
    with open(file_path, "wb") as file:
        file.write(encrypted)


def generate_strong_password(length: int = 16) -> str:
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(secrets.choice(characters) for _ in range(length))


# === GUI Class ===

class PasswordManager(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🔒 Jcreepers Password Manager")
        self.geometry("500x400")
        self.resizable(False, False)

        # Loop to get correct master password or cancel
        while True:
            master_password = ctk.CTkInputDialog(
                title="Master Password", text="Enter master password:"
            ).get_input()
            if master_password is None:  # User cancelled
                messagebox.showinfo("Exit", "Master password is required to continue.")
                self.destroy()
                return
            if not master_password:
                messagebox.showerror("Error", "Master password cannot be empty.")
                continue

            self.key = generate_key(master_password)

            if os.path.exists(DATA_FILE):
                # Try to decrypt existing data
                data = load_data(DATA_FILE, self.key)
                if data is None:
                    messagebox.showerror("Error", "Incorrect master password, please try again.")
                    continue  # prompt again
                else:
                    self.data = data
                    self.master_password = master_password
                    break
            else:
                # First time use - set master password and create empty encrypted file
                self.data = {}
                self.master_password = master_password
                save_data(DATA_FILE, self.data, self.key)
                break

        # Tabs
        self.tabview = ctk.CTkTabview(self, width=480, height=360)
        self.tabview.pack(padx=10, pady=10, expand=True, fill="both")

        self.tab_add = self.tabview.add("Add Password")
        self.tab_view = self.tabview.add("Saved Passwords")

        # Add Password Tab
        self.setup_add_tab()

        # Saved Passwords Tab
        self.setup_view_tab()

        # Graceful exit saves data
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_add_tab(self):
        ctk.CTkLabel(self.tab_add, text="Website:").grid(row=0, column=0, pady=5, padx=5, sticky="e")
        ctk.CTkLabel(self.tab_add, text="Username:").grid(row=1, column=0, pady=5, padx=5, sticky="e")
        ctk.CTkLabel(self.tab_add, text="Password:").grid(row=2, column=0, pady=5, padx=5, sticky="e")

        self.website_entry = ctk.CTkEntry(self.tab_add, width=300)
        self.website_entry.grid(row=0, column=1, pady=5, padx=5)

        self.username_entry = ctk.CTkEntry(self.tab_add, width=300)
        self.username_entry.grid(row=1, column=1, pady=5, padx=5)

        self.password_entry = ctk.CTkEntry(self.tab_add, width=210, show="*")
        self.password_entry.grid(row=2, column=1, pady=5, padx=5, sticky="w")

        generate_btn = ctk.CTkButton(
            self.tab_add, text="Generate", command=self.generate_password
        )
        generate_btn.grid(row=2, column=1, padx=5, pady=5, sticky="e")

        add_btn = ctk.CTkButton(
            self.tab_add, text="Save Password", command=self.save_password
        )
        add_btn.grid(row=3, column=0, columnspan=2, pady=10)

    def setup_view_tab(self):
        self.scrollable_frame = ctk.CTkScrollableFrame(self.tab_view, width=450, height=300)
        self.scrollable_frame.pack(pady=10)

        self.refresh_saved_passwords()

    def refresh_saved_passwords(self):
        # Clear previous widgets
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()

        if not self.data:
            ctk.CTkLabel(
                self.scrollable_frame, text="No saved passwords yet.", text_color="gray"
            ).pack(pady=5)
        else:
            for website, creds in self.data.items():
                frame = ctk.CTkFrame(self.scrollable_frame)
                frame.pack(padx=5, pady=5, fill="x")

                ctk.CTkLabel(frame, text=f"🌐 {website}", font=("Arial", 14)).pack(anchor="w", padx=5)
                ctk.CTkLabel(frame, text=f"👤 {creds['username']}").pack(anchor="w", padx=10)

                buttons_frame = ctk.CTkFrame(frame)
                buttons_frame.pack(anchor="e", padx=5, pady=3)

                ctk.CTkButton(
                    buttons_frame,
                    text="Copy Password",
                    command=lambda pw=creds["password"]: self.copy_to_clipboard(pw),
                    width=110
                ).pack(side="left", padx=2)

                ctk.CTkButton(
                    buttons_frame,
                    text="Delete",
                    fg_color="red",
                    hover_color="#ff4d4d",
                    command=lambda site=website: self.delete_password(site),
                    width=80
                ).pack(side="left", padx=2)

    def generate_password(self):
        password = generate_strong_password()
        self.password_entry.delete(0, "end")
        self.password_entry.insert(0, password)
        pyperclip.copy(password)
        messagebox.showinfo("Password Generated", "Strong password copied to clipboard.")

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not website or not username or not password:
            messagebox.showwarning("Warning", "All fields are required!")
            return

        self.data[website] = {"username": username, "password": password}
        save_data(DATA_FILE, self.data, self.key)
        messagebox.showinfo("Success", "Password saved successfully!")

        self.website_entry.delete(0, "end")
        self.username_entry.delete(0, "end")
        self.password_entry.delete(0, "end")

        self.refresh_saved_passwords()

    def delete_password(self, site):
        if site in self.data:
            confirm = messagebox.askyesno("Confirm Delete", f"Delete password for '{site}'?")
            if confirm:
                del self.data[site]
                save_data(DATA_FILE, self.data, self.key)
                self.refresh_saved_passwords()
                messagebox.showinfo("Deleted", f"Password for '{site}' deleted.")

    def copy_to_clipboard(self, password):
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard!")

    def on_close(self):
        save_data(DATA_FILE, self.data, self.key)
        self.destroy()


# === Run App ===
if __name__ == "__main__":
    app = PasswordManager()
    app.mainloop()