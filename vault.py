from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import json


class PasswordVault:
    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.keyloaded = False
        self.salt = None

    def create_key(self, path, master_password):
        try:
            self.salt = os.urandom(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=600000,
            )
            self.key = kdf.derive(master_password.encode())
            self.keyloaded = True

            key_data = {
                'salt': base64.b64encode(self.salt).decode('utf-8'),
            }
            
            with open(path, 'w') as f:
                json.dump(key_data, f)

        except Exception as e:
            raise Exception(f"Failed to create key: {str(e)}")

    def load_key(self, path, master_password):
        try:
            with open(path, 'r') as f:
                key_data = json.load(f)
            
            self.salt = base64.b64decode(key_data['salt'])
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.salt,
                iterations=600000,
            )
            self.key = kdf.derive(master_password.encode())
            self.keyloaded = True

        except Exception as e:
            raise Exception(f"Failed to load key: {str(e)}")

    def encrypt(self, data):
        if not self.keyloaded:
            raise Exception("No encryption key loaded")

        try:
            nonce = os.urandom(12)
            
            aesgcm = AESGCM(self.key)
            
            ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
            
            encrypted_data = base64.b64encode(nonce + ciphertext).decode('utf-8')
            return encrypted_data

        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt(self, encrypted_data):
        if not self.keyloaded:
            raise Exception("No encryption key loaded")

        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            nonce = encrypted_bytes[:12]
            ciphertext = encrypted_bytes[12:]
            
            aesgcm = AESGCM(self.key)
            
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode('utf-8')

        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def create_password_file(self, path, initial_values=None):
        if not self.keyloaded:
            raise Exception("No encryption key loaded")
            
        try:
            self.password_file = path
            self.password_dict = {}
            
            with open(path, 'w') as f:
                if initial_values:
                    for site, password in initial_values.items():
                        self.add_password(site, password)
                        
        except IOError as e:
            raise Exception(f"Failed to create password file: {str(e)}")

    def load_password_file(self, path):
        if not self.keyloaded:
            raise Exception("No encryption key loaded")
            
        try:
            if not os.path.exists(path):
                raise FileNotFoundError(f"Password file not found: {path}")
                
            self.password_file = path
            self.password_dict = {}
            
            with open(path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line: 
                        try:
                            site, encrypted = line.split(":", 1)
                            decrypted = self.decrypt(encrypted)
                            self.password_dict[site] = decrypted
                        except Exception as e:
                            print(f"Warning: Failed to decrypt entry for site {site}: {str(e)}")
                            
        except Exception as e:
            raise Exception(f"Failed to load password file: {str(e)}")

    def add_password(self, site, password):
        """Add a new password for a site. Returns True if successful, False otherwise."""
        if not self.keyloaded:
            raise Exception("No encryption key loaded")
            
        if not self.password_file:
            raise Exception("No password file specified")
            
        if site in self.password_dict:
            print(f"Warning: A password for the site '{site}' already exists.")
            return False
            
        if not self.validate_strength(password):
            print("Password is too weak. Requirements not met.")
            return False
            
        try:
            encrypted = self.encrypt(password)
            
            self.password_dict[site] = password
            
            with open(self.password_file, 'a') as f:
                f.write(f"{site}:{encrypted}\n")
                
            return True
            
        except Exception as e:
            print(f"Failed to add password: {str(e)}")
            return False

    def get_password(self, site):
        if not site in self.password_dict:
            return "Password not found."
        return self.password_dict[site]
    

    def validate_strength(self, password):
        SPECIAL_CHARS = '!@#$%^&*'
        MIN_LENGTH = 8
        
        requirements = [
            len(password) > MIN_LENGTH,
            any(c in SPECIAL_CHARS for c in password),
            any(c.isdigit() for c in password),
            any(c.isupper() for c in password),
            any(c.islower() for c in password)
        ]
        
        return all(requirements)