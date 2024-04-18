import json
import getpass
import random
import string
from pathlib import Path
from cryptography.fernet import Fernet
import hashlib
import datetime


class PasswordManager:
    def __init__(self, key_file='key.key', password_file='passwords.json'):
        self.key_file = key_file
        self.password_file = password_file
        self.key = self.load_or_generate_key()
        self.passwords = {}

    def load_or_generate_key(self):
        key_path = Path(self.key_file)
        if key_path.is_file():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
        return key

    def encrypt_password(self, password):
        cipher_suite = Fernet(self.key)
        return cipher_suite.encrypt(password.encode())

    def decrypt_password(self, encrypted_password):
        cipher_suite = Fernet(self.key)
        return cipher_suite.decrypt(encrypted_password).decode()

    def save_password(self, service, username, password):
        encrypted_password = self.encrypt_password(password)
        self.passwords[service] = {
            'username': username,
            'password': encrypted_password.decode(),  # Ensure str type for JSON serialization
            'expiry_date': (datetime.datetime.now() + datetime.timedelta(days=90)).strftime("%Y-%m-%d")  # Set default expiry to 90 days from now
        }
        self.save_passwords_to_file()

    def update_password(self, service, username, password):
        self.save_password(service, username, password)

    def get_password(self, service):
        if service in self.passwords:
            return self.passwords[service]['username'], hashlib.sha256(self.passwords[service]['password'].encode()).hexdigest()
        else:
            return None

    def list_services(self):
        return self.passwords.keys()

    def save_passwords_to_file(self):
        with open(self.password_file, 'w') as f:
            json.dump(self.passwords, f)

    def load_passwords_from_file(self):
        password_path = Path(self.password_file)
        if password_path.is_file():
            with open(self.password_file, 'r') as f:
                self.passwords = json.load(f)

    def is_password_strong(self, password):
        return any(char.isupper() for char in password) and any(char.isdigit() for char in password) and len(password) >= 8

    def password_strength(self, password):
        if len(password) < 8:
            return "Weak"
        elif len(password) < 12:
            return "Medium"
        else:
            return "Strong"

    def generate_captcha(self):
        captcha_chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
        captcha = ''.join(random.choice(captcha_chars) for _ in range(6))
        return captcha


def main():
    password_manager = PasswordManager()
    password_manager.load_passwords_from_file()

    while True:
        print("\n1. Save Password")
        print("2. Update Password")
        print("3. Retrieve Password")
        print("4. List All Services")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            service = input("Enter service name: ")
            username = input("Enter username: ")
            while True:
                password = getpass.getpass("Enter password (Press Enter for auto-generated strong password): ")
                if password.strip():
                    if any(char.isupper() for char in password):
                        break
                    else:
                        print("Password must contain at least one uppercase letter.")
                else:
                    password = password_manager.generate_captcha()
                    break
            password_manager.save_password(service, username, password)
            print("Password saved successfully!")
        elif choice == '2':
            service = input("Enter service name: ")
            username = input("Enter new username: ")
            while True:
                password = getpass.getpass("Enter new password (Press Enter for auto-generated strong password): ")
                if password.strip():
                    if any(char.isupper() for char in password):
                        break
                    else:
                        print("Password must contain at least one uppercase letter.")
                else:
                    password = password_manager.generate_captcha()
                    break
            password_manager.update_password(service, username, password)
            print("Password updated successfully!")
        elif choice == '3':
            service = input("Enter service name: ")
            print("Enter the following CAPTCHA to retrieve password:")
            captcha = password_manager.generate_captcha()
            print("CAPTCHA:", captcha)
            user_captcha = input("Enter CAPTCHA: ")
            if user_captcha == captcha:
                password_hash = password_manager.get_password(service)
                if password_hash:
                    print(f"Hashed Password: {password_hash}")
                else:
                    print("Password not found.")
            else:
                print("Invalid CAPTCHA. Please try again.")
        elif choice == '4':
            services = password_manager.list_services()
            if services:
                print("List of Services:")
                for service in services:
                    print(service)
            else:
                print("No services found.")
        elif choice == '5':
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
