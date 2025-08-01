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
#Standard library import
import os
import base64
import random
import string
import hashlib
from pathlib import Path
from getpass import getpass
from datetime import datetime

#Cryptography imports
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def is_encrypted():
    #Check if passwords.txt is encrpyted
    if not Path("passwords.txt").exists():
        return False
    try:
        with open("passwords.txt", "rb") as f:
            content = f.read()
            return content.startswith(b'gAAAA')
    except:
        return False

def main():
    print("Passgen\n")
    
    while True:
        print("\nMenu:\n")
        print("1. Generate new password")
        print("2. Encrypt passwords")
        print("3. Decrypt passwords")
        print("4. View passwords")
        print("5. Backup passwords")
        print("6. Exit")
        

        choice = input("\nYour choice: ")
        
        if choice == "1":
            if is_encrypted():
                print("\nCannot generate password - file is currently encrypted!")
                print("Please decrypt the file first (Option 3)")
            else:
                password = generate_password()
                save_password(password)
        elif choice == "2":
            encrypt_file()
        elif choice == "3":
            decrypt_file()
        elif choice == "4":
            view_passwords()
        elif choice == "5":
            backup_passwords()
        elif choice == "6":
            break
        else:
            print("Please enter 1-5")

def generate_password():
    #password length
    while True:
        try:
            length = int(input("\nPassword length (8-32): "))
            if 8 <= length <= 32:
                break
            print("Please enter between 8 and 32")
        except:
            print("Please enter a number")
    
    #generate password
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    password = [
        random.choice(string.ascii_lowercase),
        random.choice(string.ascii_uppercase),
        random.choice(string.digits),
        random.choice("!@#$%^&*")
    ]
    
    #Fill the rest
    password.extend(random.choice(chars) for _ in range(length - 4))
    random.shuffle(password)
    password = ''.join(password)
    
    #Display password
    print(f"Your new password: {password}")
    
    return password

def save_password(password):
    while True:
        save = input("\nSave this password to passwords.txt? (y/n): ").lower()
        if save in ['y', 'n']:
            break
        print("\nEnter y or n")
    
    if save == 'y':
        #Account name
        account = input("What account is this password for:  ").strip()
        
        #Save to file
        with open("passwords.txt", "a") as f:
            f.write(f"{account}: {password}\n")
        
        print(f"\nPassword for {account} has saved sucessfully")

def encrypt_file():
    if not Path("passwords.txt").exists():
        print("\nNo passwords file to encrypt")
        return
    
    print("\nChoose encryption method:")
    print("1. Generate new key")
    print("2. Use your own password")
    print("3. Use existing key")
    
    choice = input("Enter 1, 2, or 3 ")
    
    key = None
    
    if choice == "1":
        #Generate fernet key
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        print("\nGenerated new encryption key")
    elif choice == "2":
        #Convert password to key
        password = getpass("\nEnter your encryption password: ").encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(password).digest())
        with open("key.key", "wb") as key_file:
            key_file.write(key)
        print("\nUsing your custom password as key")
    elif choice == "3":
        if not Path("key.key").exists():
            print("\nNo existing key found")
            return
        with open("key.key", "rb") as key_file:
            key = key_file.read()
        print("\nUsing existing encryption key")
    else:
        print("Invalid choice")
        return
    
    #encrypt the file
    with open("passwords.txt", "rb") as file:
        original = file.read()
    
    fernet = Fernet(key)
    encrypted = fernet.encrypt(original)
    
    with open("passwords.txt", "wb") as encrypted_file:
        encrypted_file.write(encrypted)
    
    print("\nPasswords encrypted successfully!")

def decrypt_file():
    if not Path("passwords.txt").exists():
        print("\nNo passwords file to decrypt")
        return
    
    print("\nChoose decryption method:")
    print("1. Use key from file")
    print("2. Enter password manually")
    
    method = input("Enter 1 or 2: ")
    
    key = None
    if method == "1":
        if not Path("key.key").exists():
            print("\nNo key file found")
            return
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    elif method == "2":
        password = getpass("\nEnter your decryption password: ").encode()
        key = base64.urlsafe_b64encode(hashlib.sha256(password).digest())
    else:
        print("Invalid choice")
        return
    
    try:
        #Decrypt the file
        with open("passwords.txt", "rb") as file:
            encrypted = file.read()
        
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        
        with open("passwords.txt", "wb") as decrypted_file:
            decrypted_file.write(decrypted)
        
        print("\nPasswords decrypted successfully")
    except:
        print("\nFailed to decrypt, wrong key or corrupted file")

def view_passwords():
    file = Path("passwords.txt")
    if file.exists():
        print("\nSaved Passwords: ")
        print("═" * 50)
        with open("passwords.txt", "r") as f:
            print(f.read())
        print("═" * 50)
    else:
        print("\nNo passwords found\n")

def backup_passwords():
    #Timestamp copy
    if not Path("passwords.txt").exists():
        print("\nNo passwords file to backup")
        return
    
    timestamp = datetime.now().strftime("%Y-%m%d_$H%M%S")
    backup_file = f"passwords_backup_{timestamp}.txt"

    try:
        #Check if file is encrypted
        with open("passwords.txt", "rb") as original:
            content = original.read()
            if content.startswith(b'gAAAA'):
                print("\nFile is encrypted, decrypt first")
                return
        
        #Copy file
        with open("passwords.txt", "r") as original, open(backup_file, "w") as backup:
            backup.write(original.read())

        print(f"\nBackup saved as {backup_file}")
    except Exception as e:
        print(f"\nfailed to backup: {str(e)}")


"""
-TODO-
    -Add password strength checker
    -Availability to decrypt backups
    -Class
    -Settings
"""
if __name__ == "__main__":
    main()