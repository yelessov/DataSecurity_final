from src.auth_manager import AuthManager
from src.brute_force import ParallelCracker
from src.audit_chain import Blockchain  # <--- ИМПОРТ

def main():
    # Инициализация модулей
    auth = AuthManager()
    cracker = ParallelCracker()
    audit = Blockchain() # <--- ЗАПУСК БЛОКЧЕЙНА

    while True:
        print("\n=== SYSTEM MENU ===")
        print("1. [ADMIN] Зарегистрировать пользователя")
        print("2. [HACKER] Атаковать пользователя (Brute-force)")
        print("3. [AUDIT] Проверить целостность Блокчейна")
        print("4. Выход")
        
        choice = input("Выбор: ")

        if choice == '1':
            user = input("Имя пользователя: ")
            pwd = input("Пароль: ")
            
            if auth.register(user, pwd):
                # Логируем успех в блокчейн
                audit.add_event(f"User Registered: {user}")
            else:
                audit.add_event(f"Registration Failed: User {user} exists")
            
        elif choice == '2':
            target_user = input("Кого ломаем? (Имя): ")
            user_data = auth.get_user_data(target_user)
            
            if not user_data:
                print("[-] Такого пользователя нет.")
                audit.add_event(f"Attack Attempt Failed: User {target_user} not found")
                continue
            
            # Логируем начало атаки
            audit.add_event(f"SECURITY ALERT: Brute-force started on {target_user}")
            
            print(f"[*] Цель: {target_user}")
            result = cracker.crack(user_data['hash'], user_data['salt'])
            
            if result:
                audit.add_event(f"CRITICAL: User {target_user} COMPROMISED. Password: {result}")
            else:
                audit.add_event(f"Attack Finished: Password for {target_user} not found")
                
        elif choice == '3':
            print("\n[*] Запуск аудита безопасности...")
            if audit.is_chain_valid():
                print("[OK] Блокчейн валиден. Данные не изменялись.")
            else:
                print("[!!!] ВНИМАНИЕ: БЛОКЧЕЙН ПОВРЕЖДЕН! ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО!")

        elif choice == '4':
            break

if __name__ == "__main__":
    main()