"""
PassGen - local password generator

by @p0sco
https://github.com/p0sco/PassGen

###########################
-Secure password generation
-Password encryption
-Password saving
-Password backups
###########################
"""

import os
import base64
import random
import string
import hashlib
from pathlib import Path
from getpass import getpass
from datetime import datetime


from cryptography.fernet import Fernet


BASE_DIR = Path(__file__).parent.resolve()


class PasswordManager:
    def __init__(self, filename="passwords.txt"):
        self.filename = BASE_DIR / filename

    def is_encrypted(self):
        """Check if the main password file is already encrypted"""
        if not self.filename.exists():
            return False
        try:
            with open(self.filename, "rb") as f:
                return f.read().startswith(b"gAAAA")
        except:
            return False

    def generate_password(self):
        while True:
            try:
                length = int(input("\nPassword length (8-32): "))
                if 8 <= length <= 32:
                    break
                print("Please enter between 8 and 32")
            except:
                print("Please enter a number")

        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        password = [
            random.choice(string.ascii_lowercase),
            random.choice(string.ascii_uppercase),
            random.choice(string.digits),
            random.choice("!@#$%^&*")
        ]
        password.extend(random.choice(chars) for _ in range(length - 4))
        random.shuffle(password)
        password = ''.join(password)
        print(f"Your new password: {password}")
        return password

    def save_password(self, password):
        while True:
            save = input("\nSave this password to passwords.txt? (y/n): ").lower()
            if save in ['y', 'n']:
                break
            print("\nEnter y or n")

        if save == 'y':
            account = input("What account is this password for:  ").strip()
            with open(self.filename, "a") as f:
                f.write(f"{account}: {password}\n")
            print(f"\nPassword for {account} has saved successfully")

    def _derive_key(self, password: str):
        """Derive a Fernet key from a password."""
        password_bytes = password.encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(password_bytes).digest())
        return Fernet(key)

    def encrypt_file(self):
        if not self.filename.exists():
            print("\nNo passwords file to encrypt")
            return

        if self.is_encrypted():
            print("\nFile is already encrypted. Cannot encrypt again. ")
            return

        password = input("\nEnter a password to encrypt your file: ")
        confirm = getpass("Confirm password: ")
        if password != confirm:
            print("\nPasswords do not match. Encryption canceled.")
            return

        fernet = self._derive_key(confirm)
        with open(self.filename, "rb") as file:
            original = file.read()
        encrypted = fernet.encrypt(original)
        with open(self.filename, "wb") as encrypted_file:
            encrypted_file.write(encrypted)
        print("\nPasswords encrypted successfully!")

    def decrypt_file(self):
        if not self.filename.exists():
            print("\nNo passwords file to decrypt")
            return

        if not self.is_encrypted():
            print("\nFile is not encrypted! Nothing to decrypt.")
            return

        password = getpass("\nEnter your decryption password: ")
        fernet = self._derive_key(password)

        try:
            with open(self.filename, "rb") as file:
                encrypted = file.read()
            decrypted = fernet.decrypt(encrypted)
            with open(self.filename, "wb") as decrypted_file:
                decrypted_file.write(decrypted)
            print("\nPasswords decrypted successfully")
        except:
            print("\nFailed to decrypt. Wrong password or corrupted file.")

    def view_passwords(self):
        if self.filename.exists():
            print("\nSaved Passwords: ")
            print("â" * 50)
            with open(self.filename, "r") as f:
                print(f.read())
            print("â" * 50)
        else:
            print("\nNo passwords found\n")

    def backup_passwords(self):
        if not self.filename.exists():
            print("\nNo passwords file to backup")
            return

        today = datetime.now().strftime('%Y-%m-%d')
        existing_backups = sorted(BASE_DIR.glob(f"*-Password_Backup({today}).txt"))

        # Read current password file content
        with open(self.filename, "r") as f:
            current_content = f.read()

        # Check if identical backup already exists
        for backup in existing_backups:
            with open(backup, "r") as bf:
                if bf.read() == current_content:
                    print("\nBackup already exists for the current file.")
                    return

        # Determine the next index by parsing existing filenames
        indices = []
        for backup in existing_backups:
            try:
                index = int(backup.name.split("-")[0])
                indices.append(index)
            except:
                continue
        next_index = max(indices, default=1) + 1

        backup_file = BASE_DIR / f"{next_index}-Password_Backup({today}).txt"

        try:
            with open(self.filename, "r") as original, open(backup_file, "w") as backup:
                backup.write(original.read())
            print(f"\nBackup saved as {backup_file.name}")
        except Exception as e:
            print(f"\nFailed to backup: {str(e)}")


class BackupManager:
    def __init__(self, pm: PasswordManager):
        self.pm = pm

    def is_backup_encrypted(self, file_path):
        """Check if a backup is encrypted"""
        try:
            with open(file_path, "rb") as f:
                return f.read().startswith(b"gAAAA")
        except:
            return False

    def encrypt_backups(self):
        #List backups
        backups = sorted(BASE_DIR.glob("*-Password_Backup(*).txt"))
        if not backups:
            print("\nNo backups found")
            return

        print("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            print(f"{i} - {backup.name}")

        #Get user choice
        choice = input("\nEnter backup number to encrypt or 'all' for all: ").strip().lower()
        if choice == "all":
            selected_backups = backups
        else:
            try:
                index = int(choice) - 1
                selected_backups = [backups[index]]
            except:
                print("\nInvalid selection")
                return

        already_encrypted = [b for b in selected_backups if self.is_backup_encrypted(b)]
        if already_encrypted:
            for b in already_encrypted:
                print(f"{b.name} is already encrypted, skipping encryption.")
            selected_backups = [b for b in selected_backups if not self.is_backup_encrypted(b)]
            if not selected_backups:
                print("\nNo backups left to encrypt. Skipping")
                return
            

        #Get Password
        password = input("\nEnter password to encrypt selected backups: ")
        confirm = getpass("\nConfirm password: ")
        if password != confirm:
            print("\nPasswords do not match. Encryption canceled.")
            return

        fernet = self.pm._derive_key(confirm)

        for backup in selected_backups:
            if self.is_backup_encrypted(backup):
                print(f"{backup.name} is already encrypted, skipping.")
                continue
            with open(backup, "rb") as file:
                data = file.read()
            encrypted = fernet.encrypt(data)
            with open(backup, "wb") as file:
                file.write(encrypted)

        print("\nSelected backups encrypted successfully")

    def decrypt_backups(self):
        backups = sorted(BASE_DIR.glob("*-Password_Backup(*).txt"))
        if not backups:
            print("\nNo backups found")
            return

        #Backup numbered list
        print("\nAvailable backups:")
        for i, backup in enumerate(backups, 1):
            print(f"{i} - {backup.name}")

        #Ask for which backup
        choice = input("\nEnter backup number to decrypt or 'all' for all: ").strip().lower()
        if choice == "all":
            selected_backups = backups
        else:
            try:
                index = int(choice) - 1
                if index < 0 or index >= len(backups):
                    print("\nInvalid selection")
                    return
                selected_backups = [backups[index]]
            except:
                print("\nInvalid selection")
                return

        #Get Password 
        password = getpass("\nEnter password to decrypt backups: ")
        fernet = self.pm._derive_key(password)

        for backup in selected_backups:
            if not self.is_backup_encrypted(backup):
                print(f"{backup.name} is not encrypted, skipping.")
                continue
            try:
                with open(backup, "rb") as file:
                    data = file.read()
                decrypted = fernet.decrypt(data)
                with open(backup, "wb") as file:
                    file.write(decrypted)
                print(f"Decrypted {backup.name} successfully")
            except:
                print(f"\nFailed to decrypt {backup.name} (wrong password or corrupted file)")

        print("\nSelected backup(s) decryption completed.")


class PassGen:
    def __init__(self):
        self.pm = PasswordManager()
        self.bm = BackupManager(self.pm)

    def menu(self):
        print("Passgen\n")
        while True:
            print("\nMenu:\n")
            print("1. Generate new password")
            print("2. Encrypt passwords")
            print("3. Decrypt passwords")
            print("4. View passwords")
            print("5. Backup passwords")
            print("6. Encrypt backups")
            print("7. Decrypt backups")
            print("8. Exit")

            choice = input("\nYour choice: ")
            if choice == "1":
                if self.pm.is_encrypted():
                    print("\nCannot generate password - file is currently encrypted!")
                    print("Please decrypt the file first (Option 3)")
                else:
                    password = self.pm.generate_password()
                    self.pm.save_password(password)
            elif choice == "2":
                self.pm.encrypt_file()
            elif choice == "3":
                self.pm.decrypt_file()
            elif choice == "4":
                self.pm.view_passwords()
            elif choice == "5":
                self.pm.backup_passwords()
            elif choice == "6":
                self.bm.encrypt_backups()
            elif choice == "7":
                self.bm.decrypt_backups()
            elif choice == "8":
                break
            else:
                print("Invalid Option, Please enter 1-8")


if __name__ == "__main__":
    app = PassGen()
    app.menu()
