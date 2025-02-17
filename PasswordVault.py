import argparse
from getpass import getpass
from cryptography.fernet import Fernet
from vault import PasswordVault
import secrets
import string
import pyperclip
import threading


def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)):
            return password
def copy_to_clipboard(password):
    pyperclip.copy(password)
    print("Password copied to clipboard (will clear in 30s)")
    threading.Timer(30.0, pyperclip.copy, args=('',)).start()

def create_key(pm, path):
    while(1):
        master_password = getpass("Enter master password: ")
        confirm_password = getpass("Confirm master password: ")
        if master_password != confirm_password:
            print("Passwords do not match!\nTry Again!!!")
            continue
        break
    
    pm.create_key(path, master_password)
    print(f"Key saved to {path}")
    return True

def load_key(pm, path):
    master_password = getpass("Enter master password: ")
    try:
        pm.load_key(path, master_password)
        print(f"Key loaded from {path}")
        return True
    except Exception as e:
        print(f"Failed to load key: {str(e)}")
        return False

def create_password_file(pm, path):
    pm.create_password_file(path)
    print(f"Password file created at {path}")

def load_password_file(pm, path):
    pm.load_password_file(path)
    print(f"Password file loaded from {path}")

def add_password(pm, site, password):
    if pm.validate_strength(password):
        pm.add_password(site, password)
        print(f"Password for {site} added successfully.")
    else:
        print("Password is weak. It should be at least 8 characters long, contain special characters, uppercase letters, lowercase letters, and numbers.")

def get_password(pm, site):
    password = pm.get_password(site)
    copy_to_clipboard(password)

    print(f"Password for {site}: {password}")

def list_sites(pm):
    print("Saved Sites:")
    for site in pm.password_dict:
        print(site)

def main():
    parser = argparse.ArgumentParser(description="Password Vault CLI")

    # Key file arguments
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("-nKf", "--new-key-file", type=str, help="Path to save the new key file")
    key_group.add_argument("-Kf", "--key-file", type=str, help="Path to an existing key file")

    # Password file arguments
    pwd_group = parser.add_mutually_exclusive_group(required=True)
    pwd_group.add_argument("-nPf", "--new-password-file", type=str, help="Path to create a new password file")
    pwd_group.add_argument("-Pf", "--password-file", type=str, help="Path to the existing password file")

    # Actions
    parser.add_argument("-addP", "--add-password", nargs='?', const='manual', help="Add password. Use 'generate' to create one")
    parser.add_argument("-getP", "--get-password", action="store_true", help="Get a password for a site")
    parser.add_argument("-listsites", "--list-sites", action="store_true", help="List all saved sites")

    args = parser.parse_args()
    pm = PasswordVault()

    if args.new_key_file:
        create_key(pm, args.new_key_file)
        load_key(pm, args.new_key_file)
    else:
        load_key(pm, args.key_file)

    # Handle password file
    if args.new_password_file:
        create_password_file(pm, args.new_password_file)
        load_password_file(pm, args.new_password_file)
    else:
        load_password_file(pm, args.password_file)

    # Handle actions
    if args.add_password:
        site = input("Enter the site: ").strip()
        
        if args.add_password.lower() == 'generate':
            # Generate password that meets requirements
            password = generate_password()
            print(f"\nGenerated password: {password}")
            
            # Confirm usage
            if input("Use this password? (y/n): ").lower() == 'y':
                if pm.add_password(site, password):
                    print(f"Password for {site} added successfully!")
                else:
                    print("Failed to add password")
            else:
                print("Password generation canceled")
        else:
            # Existing manual entry flow
            password = getpass("Enter the password: ").strip()
            add_password(pm, site, password)
    elif args.get_password:
        site = input("Enter the site: ").strip()
        get_password(pm, site)
    elif args.list_sites:
        list_sites(pm)

if __name__ == "__main__":
    main()

