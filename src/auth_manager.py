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

        # Генерируем соль (защита)
        salt = secrets.token_hex(16)
        # Хешируем
        combined = password + salt
        p_hash = hashlib.sha256(combined.encode()).hexdigest()

        # Сохраняем в "Базу"
        self.users[username] = {
            'salt': salt,
            'hash': p_hash
        }
        self._save_db()
        print(f"[+] Пользователь {username} успешно зарегистрирован.")
        return True

    def get_user_data(self, username):
        return self.users.get(username)