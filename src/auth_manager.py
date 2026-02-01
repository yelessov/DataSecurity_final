import hashlib
import secrets
import json
import os

DB_PATH = 'data/users.json'

class AuthManager:
    def __init__(self):
        self.users = self._load_db()

    def _load_db(self):
        if not os.path.exists(DB_PATH):
            return {}
        try:
            with open(DB_PATH, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    def _save_db(self):
        with open(DB_PATH, 'w') as f:
            json.dump(self.users, f, indent=4)

    def register(self, username, password):
        if username in self.users:
            print(f"[-] Ошибка: Пользователь {username} уже существует.")
            return False

        # Create a cryptographically secure random salt
        salt = secrets.token_hex(16)
        # Hash the password together with the salt using SHA-256
        combined = password + salt
        p_hash = hashlib.sha256(combined.encode()).hexdigest()

        # Store the new user record in our JSON "database"
        self.users[username] = {
            'salt': salt,
            'hash': p_hash
        }
        self._save_db()
        print(f"[+] Пользователь {username} успешно зарегистрирован.")
        return True

    def get_user_data(self, username):
        return self.users.get(username)

    def save_secret(self, username, encrypted_secret):
        if username in self.users:
            self.users[username]['secret'] = encrypted_secret
            self._save_db()
            return True
        return False

    def get_secret(self, username):
        if username in self.users:
            return self.users[username].get('secret') # Returns None if the user hasn't saved a secret
        return None