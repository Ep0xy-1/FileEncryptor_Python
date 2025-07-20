import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import base64
import secrets
import json
from datetime import datetime
  
SALT_SIZE = 16
KEY_SIZE = 32
ITERATIONS = 100_000
VAULT_FILE = "password_vault.dat"

class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure File Encryptor + Vault")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        self.tab_control = ttk.Notebook(root)
        self.tab_main = ttk.Frame(self.tab_control)
        self.tab_vault = ttk.Frame(self.tab_control)

        self.tab_control.add(self.tab_main, text="Encrypt/Decrypt")
        self.tab_control.add(self.tab_vault, text="🔑 Saved Passwords")
        self.tab_control.pack(expand=1, fill="both")

        # --- Main tab widgets ---
        tk.Button(self.tab_main, text="🔒 Encrypt File", command=self.encrypt_file, width=30).pack(pady=10)
        tk.Button(self.tab_main, text="🔓 Decrypt File", command=self.decrypt_file, width=30).pack(pady=10)
        tk.Button(self.tab_main, text="📄 Instructions", command=self.show_instructions, width=30).pack(pady=10)

        # --- Vault tab widgets ---
        tk.Button(self.tab_vault, text="🔐 Unlock Vault", command=self.unlock_vault, width=25).pack(pady=10)
        self.vault_list = tk.Text(self.tab_vault, height=15, width=55, state='disabled')
        self.vault_list.pack(pady=5)

    def derive_key(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
        if not password:
            return

        with open(filepath, 'rb') as f:
            data = f.read()

        salt = secrets.token_bytes(SALT_SIZE)
        key = self.derive_key(password, salt)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)

        out_data = salt + nonce + ciphertext
        out_path = filepath + ".enc"

        with open(out_path, 'wb') as f:
            f.write(out_data)

        save = messagebox.askyesno("Save Password?", "Save password to local vault?")
        if save:
            self.save_password_entry(filepath, password)

        messagebox.showinfo("Success", f"File encrypted as:\n{out_path}")

    def decrypt_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
        if not filepath:
            return

        password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
        if not password:
            return

        with open(filepath, 'rb') as f:
            content = f.read()

        try:
            salt = content[:SALT_SIZE]
            nonce = content[SALT_SIZE:SALT_SIZE + 12]
            ciphertext = content[SALT_SIZE + 12:]

            key = self.derive_key(password, salt)
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            original_path = filepath.replace(".enc", ".decrypted")
            with open(original_path, 'wb') as f:
                f.write(plaintext)

            messagebox.showinfo("Success", f"File decrypted to:\n{original_path}")

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{str(e)}")

    def save_password_entry(self, filename, password):
        master = simpledialog.askstring("Master Password", "Set or enter master password:", show='*')
        if not master:
            return

        salt = secrets.token_bytes(SALT_SIZE)
        key = self.derive_key(master, salt)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)

        entry = {
            "file": os.path.basename(filename),
            "password": password,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M")
        }

        data = json.dumps(entry).encode()
        encrypted = aesgcm.encrypt(nonce, data, None)
        vault_entry = base64.b64encode(salt + nonce + encrypted).decode()

        with open(VAULT_FILE, 'a') as f:
            f.write(vault_entry + "\n")

    def unlock_vault(self):
        self.vault_list.config(state='normal')
        self.vault_list.delete("1.0", tk.END)

        if not os.path.exists(VAULT_FILE):
            self.vault_list.insert(tk.END, "No saved passwords found.")
            self.vault_list.config(state='disabled')
            return

        master = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
        if not master:
            return

        with open(VAULT_FILE, 'r') as f:
            lines = f.readlines()

        for line in lines:
            try:
                data = base64.b64decode(line.strip())
                salt = data[:SALT_SIZE]
                nonce = data[SALT_SIZE:SALT_SIZE + 12]
                ciphertext = data[SALT_SIZE + 12:]

                key = self.derive_key(master, salt)
                aesgcm = AESGCM(key)
                decrypted = aesgcm.decrypt(nonce, ciphertext, None)
                entry = json.loads(decrypted.decode())

                self.vault_list.insert(tk.END, f"📁 File: {entry['file']}\n🔑 Password: {entry['password']}\n📅 Saved: {entry['date']}\n\n")
            except:
                self.vault_list.insert(tk.END, "⚠️ Failed to decrypt an entry. Wrong master password?\n\n")

        self.vault_list.config(state='disabled')

    def show_instructions(self):
        messagebox.showinfo("Instructions",
            "1. 🔒 Encrypt File - Select file, enter password, choose to save.\n"
            "2. 🔓 Decrypt File - Select .enc file and enter the correct password.\n"
            "3. 🔑 Saved Passwords - View saved entries after unlocking with your master password.\n"
            "⚠️ All passwords are AES-encrypted locally with strong key derivation."
        )


if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
