# 🔐 Secure File Encryptor + Vault (Python + Tkinter)

A production-ready GUI application built in Python using Tkinter that allows you to **encrypt and decrypt files** securely using **AES-256-GCM**, and manage your credentials via a **password vault** protected by a **master password**.
 
---

## 📦 Features

| Feature | Description |
|--------|-------------|
| 🔒 File Encryption | AES-256-GCM encryption with secure key derivation (PBKDF2-HMAC-SHA256) |
| 🔓 File Decryption | Easily decrypt `.enc` files with the correct password |
| 🔐 Password Vault | Save file passwords locally (encrypted with a master password) |
| 📄 Vault Viewer | View saved passwords and metadata securely inside the GUI |
| 🧠 Memory Safety | No plaintext password is stored in files |
| 🧰 GUI | Intuitive interface using `tkinter`, `tk.simpledialog`, `tk.messagebox`, and `ttk.Notebook` |

---

## 🛡️ How It Works

- 🔑 A password is requested for encryption. You may save it afterward.
- 🔐 Saved passwords are encrypted with a **master password** using `AESGCM`.
- 🔁 For every saved entry:
  - A new salt, nonce, and encrypted block is generated
  - It is encoded in base64 and saved line-by-line in `password_vault.dat`

---

## 🖥️ GUI Tabs

### 1. Encrypt/Decrypt
- `Encrypt File`: Choose a file → enter password → save encrypted version.
- `Decrypt File`: Choose `.enc` file → enter password → file decrypted to `.decrypted`.
- `Instructions`: View help guide.

### 2. 🔑 Saved Passwords
- Unlock vault with your **master password**
- View all saved password entries with:
  - Filename
  - Encrypted password (decrypted on unlock)
  - Date/time

---

## 🔧 Requirements

> Python 3.8+
> 
> Required packages:
```bash```
pip install cryptography

## 🧪 How to Run

python secure_encryptor_vault.py
If you're using a .pyw version, just double-click to run without terminal.

## 📂 File Structure

secure_encryptor_vault.py        # Main Python file
password_vault.dat               # Auto-created; stores encrypted entries

## 🔐 Security Considerations
Vault entries are encrypted using AES-256-GCM

- Keys are derived via PBKDF2 with:
- 16-byte salt
- 100,000 iterations
- SHA256 hash
- No password is stored in plaintext — even in memory, only decoded when needed
- Vault file is a plain .dat but data inside is encoded and encrypted

## 🧠 Future Ideas
Auto-timeout for decrypted password views

Integrate biometric unlocking (if device supports)

Add categories or tags to vault entries

Export vault entries securely

# 👨‍💻 Author
Cybersecurity-ready project built by me, maintained for production and educational purposes.

created in 20/07/2025
