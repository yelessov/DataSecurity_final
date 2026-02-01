from src.auth_manager import AuthManager
from src.brute_force import ParallelCracker
from src.audit_chain import Blockchain
import src.encryption as crypto # <--- IMPORT OUR NEW MODULE

def user_dashboard(username, password, auth, audit):
    """Simple console menu for a logged-in user."""
    while True:
        print(f"\n--- ЛИЧНЫЙ КАБИНЕТ: {username} ---")
        print("1. Посмотреть мой секрет (Расшифровать)")
        print("2. Записать новый секрет (Зашифровать)")
        print("3. Выйти")
        
        choice = input("Действие: ")
        
        user_data = auth.get_user_data(username)
        salt = user_data['salt']

        if choice == '1':
            encrypted_blob = auth.get_secret(username)
            if encrypted_blob:
                print("\n[*] Attempting to decrypt data with your password...")
                # We decrypt the secret right here in memory; the derived key is never persisted.
                secret = crypto.decrypt_secret(password, salt, encrypted_blob)
                print(f"[SECRET] Ваша запись: {secret}")
                audit.add_event(f"User {username} accessed their encrypted secret")
            else:
                print("[-] У вас еще нет сохраненных секретов.")

        elif choice == '2':
            text = input("Введите секретный текст (номер карты, пин-код...): ")
            # Encrypt the provided secret text using the user's password-derived key
            encrypted_data = crypto.encrypt_secret(password, salt, text)
            # Store only the resulting ciphertext in the user database
            auth.save_secret(username, encrypted_data)
            print("[+] Секрет зашифрован и сохранен.")
            audit.add_event(f"User {username} updated their encrypted secret")

        elif choice == '3':
            break

def main():
    auth = AuthManager()
    cracker = ParallelCracker()
    audit = Blockchain()

    while True:
        print("\n=== SYSTEM MENU ===")
        print("1. [ADMIN] Регистрация")
        print("2. [USER] Вход в систему (Login)")
        print("3. [HACKER] Атака (Brute-force)")
        print("4. [AUDIT] Блокчейн лог")
        print("5. Выход")
        
        choice = input("Выбор: ")

        if choice == '1':
            user = input("User: ")
            pwd = input("Pass: ")
            if auth.register(user, pwd):
                audit.add_event(f"Registered: {user}")

        elif choice == '2':
            # CLI login flow to allow access to encryption features
            user = input("User: ")
            pwd = input("Pass: ")
            
                # We need to verify the password by recomputing the stored hash
            user_data = auth.get_user_data(user)
            
            if user_data:
                # Simple hash check: recompute and compare
                from src.encryption import derive_key # can be reused or hashed as before
                # For simplicity we reuse the same hash comparison approach used elsewhere
                # In a production app you'd use a proper authentication flow or attempt decryption
                import hashlib
                check_hash = hashlib.sha256((pwd + user_data['salt']).encode()).hexdigest()
                
                if check_hash == user_data['hash']:
                    print(f"[+] Добро пожаловать, {user}!")
                    audit.add_event(f"User Login Success: {user}")
                    # Enter the user dashboard
                    user_dashboard(user, pwd, auth, audit)
                else:
                    print("[-] Неверный пароль.")
                    audit.add_event(f"Login Failed: {user}")
            else:
                print("[-] Пользователь не найден.")

        elif choice == '3':
            # ... old hacker code ...
            target = input("Цель: ")
            data = auth.get_user_data(target)
            if data:
                audit.add_event(f"Brute-force started on {target}")
                res = cracker.crack(data['hash'], data['salt'])
                if res:
                    print(f"Пароль: {res}")
                    audit.add_event(f"User {target} COMPROMISED")
            else:
                print("Не найден")

        elif choice == '4':
            if audit.is_chain_valid():
                print("Блокчейн OK")
            else:
                print("Блокчейн ПОВРЕЖДЕН")
        
        elif choice == '5':
            break

if __name__ == "__main__":
    main()