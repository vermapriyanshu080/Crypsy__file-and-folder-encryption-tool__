import os
import json
import base64
import sys
import argparse
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import getpass
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class FileVault:
    def __init__(self):
        self.metadata_file = "vault_metadata.json"
        self.metadata = self._load_metadata()
        self.salt = b'vault_salt_123'  # In production, use a secure random salt

    def _load_metadata(self):
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, 'r') as f:
                return json.load(f)
        return {}

    def _save_metadata(self):
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=4)

    def _derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_file(self, file_path, password=None):
        if not os.path.exists(file_path):
            print(f"Error: File {file_path} does not exist.")
            return False

        if password is None:
            password = getpass.getpass("Enter password for encryption: ")

        try:
            key = self._derive_key(password)
            fernet = Fernet(key)

            with open(file_path, 'rb') as f:
                file_data = f.read()

            encrypted_data = fernet.encrypt(file_data)
            encrypted_file_path = f"{file_path}.encrypted"

            with open(encrypted_file_path, 'wb') as f:
                f.write(encrypted_data)

            self.metadata[encrypted_file_path] = {
                'original_name': file_path,
                'encrypted_date': datetime.now().isoformat(),
                'last_opened': None,
                'locked': True
            }
            self._save_metadata()

            print(f"File encrypted successfully: {encrypted_file_path}")
            return True

        except Exception as e:
            print(f"Error during encryption: {str(e)}")
            return False

    def decrypt_file(self, encrypted_file_path, password=None):
        if not os.path.exists(encrypted_file_path):
            print(f"Error: Encrypted file {encrypted_file_path} does not exist.")
            return False

        if encrypted_file_path not in self.metadata:
            print("Error: File metadata not found.")
            return False

        if password is None:
            password = getpass.getpass("Enter password for decryption: ")

        try:
            key = self._derive_key(password)
            fernet = Fernet(key)

            with open(encrypted_file_path, 'rb') as f:
                encrypted_data = f.read()

            decrypted_data = fernet.decrypt(encrypted_data)
            original_path = self.metadata[encrypted_file_path]['original_name']
            
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)

            self.metadata[encrypted_file_path]['last_opened'] = datetime.now().isoformat()
            self._save_metadata()

            print(f"File decrypted successfully: {original_path}")
            return True

        except Exception as e:
            print(f"Error during decryption: {str(e)}")
            return False

    def show_metadata(self, file_path):
        if file_path in self.metadata:
            print("\nFile Metadata:")
            print(f"Original Name: {self.metadata[file_path]['original_name']}")
            print(f"Encrypted Date: {self.metadata[file_path]['encrypted_date']}")
            print(f"Last Opened: {self.metadata[file_path]['last_opened'] or 'Never'}")
            print(f"Locked: {self.metadata[file_path]['locked']}")
        else:
            print("No metadata found for this file.")

class FileVaultGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Encrypted File Vault")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')

        self.vault = FileVault()
        self._create_widgets()
        self._create_styles()

    def _create_styles(self):
        style = ttk.Style()
        style.configure('Custom.TButton', padding=10, font=('Helvetica', 10))
        style.configure('Custom.TLabel', font=('Helvetica', 10))
        style.configure('Title.TLabel', font=('Helvetica', 16, 'bold'))

    def _create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(main_frame, text="Encrypted File Vault", style='Title.TLabel')
        title_label.pack(pady=20)

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)

        # Encrypt button
        encrypt_btn = ttk.Button(
            button_frame,
            text="Encrypt File",
            command=self._encrypt_file,
            style='Custom.TButton',
            width=20
        )
        encrypt_btn.pack(pady=10)

        # Decrypt button
        decrypt_btn = ttk.Button(
            button_frame,
            text="Decrypt File",
            command=self._decrypt_file,
            style='Custom.TButton',
            width=20
        )
        decrypt_btn.pack(pady=10)

        # View Metadata button
        metadata_btn = ttk.Button(
            button_frame,
            text="View File Metadata",
            command=self._show_metadata,
            style='Custom.TButton',
            width=20
        )
        metadata_btn.pack(pady=10)

        # Status frame
        self.status_frame = ttk.Frame(main_frame)
        self.status_frame.pack(fill=tk.X, pady=20)

        self.status_label = ttk.Label(
            self.status_frame,
            text="Ready",
            style='Custom.TLabel'
        )
        self.status_label.pack()

    def _get_password(self, title):
        password_window = tk.Toplevel(self.root)
        password_window.title(title)
        password_window.geometry("300x150")
        password_window.transient(self.root)
        password_window.grab_set()

        password_var = tk.StringVar()
        result = {'password': None}

        def on_ok():
            result['password'] = password_var.get()
            password_window.destroy()

        ttk.Label(password_window, text="Enter password:").pack(pady=10)
        password_entry = ttk.Entry(password_window, textvariable=password_var, show="*")
        password_entry.pack(pady=10)
        password_entry.focus()

        ttk.Button(password_window, text="OK", command=on_ok).pack(pady=10)

        self.root.wait_window(password_window)
        return result['password']

    def _encrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select file to encrypt",
            filetypes=[("All files", "*.*")]
        )
        
        if not file_path:
            return

        password = self._get_password("Encryption Password")
        if not password:
            return

        try:
            if self.vault.encrypt_file(file_path, password):
                self.status_label.config(text=f"File encrypted successfully: {file_path}.encrypted")
                messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {file_path}.encrypted")
        except Exception as e:
            self.status_label.config(text=f"Error during encryption: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def _decrypt_file(self):
        file_path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Encrypted files", "*.encrypted")]
        )
        
        if not file_path:
            return

        password = self._get_password("Decryption Password")
        if not password:
            return

        try:
            if self.vault.decrypt_file(file_path, password):
                self.status_label.config(text=f"File decrypted successfully: {self.vault.metadata[file_path]['original_name']}")
                messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {self.vault.metadata[file_path]['original_name']}")
        except Exception as e:
            self.status_label.config(text=f"Error during decryption: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def _show_metadata(self):
        file_path = filedialog.askopenfilename(
            title="Select encrypted file",
            filetypes=[("Encrypted files", "*.encrypted")]
        )
        
        if not file_path:
            return

        if file_path in self.vault.metadata:
            metadata = self.vault.metadata[file_path]
            metadata_text = f"""
File Metadata:
Original Name: {metadata['original_name']}
Encrypted Date: {metadata['encrypted_date']}
Last Opened: {metadata['last_opened'] or 'Never'}
Locked: {metadata['locked']}
"""
            messagebox.showinfo("File Metadata", metadata_text)
        else:
            messagebox.showinfo("File Metadata", "No metadata found for this file.")

def main():
    parser = argparse.ArgumentParser(description='Encrypted File Vault')
    parser.add_argument('--cli', action='store_true', help='Use command-line interface instead of GUI')
    args = parser.parse_args()

    if args.cli:
        vault = FileVault()
        while True:
            print("\n=== Encrypted File Vault ===")
            print("1. Encrypt a file")
            print("2. Decrypt a file")
            print("3. Show file metadata")
            print("4. Exit")
            
            choice = input("\nEnter your choice (1-4): ")
            
            if choice == '1':
                file_path = input("Enter the path of the file to encrypt: ")
                vault.encrypt_file(file_path)
            
            elif choice == '2':
                file_path = input("Enter the path of the encrypted file: ")
                vault.decrypt_file(file_path)
            
            elif choice == '3':
                file_path = input("Enter the path of the encrypted file: ")
                vault.show_metadata(file_path)
            
            elif choice == '4':
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice. Please try again.")
    else:
        try:
            import tkinter as tk
            from tkinter import ttk, filedialog, messagebox
            root = tk.Tk()
            app = FileVaultGUI(root)
            root.mainloop()
        except ImportError:
            print("Error: tkinter is not installed. Please install it or use --cli option.")
            sys.exit(1)

if __name__ == "__main__":
    main() 