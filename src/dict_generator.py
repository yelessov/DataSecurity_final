import random
import string

def generate_big_dictionary(filename='data/dictionary.txt', size=1_000_000):
    print(f"[*] Генерирую словарь на {size} слов...")
    
    # 1. Базовые слова, которые мы точно хотим найти
    real_passwords = ["password123", "admin", "secret", "mypassword", "testing1_pass"]
    
    with open(filename, 'w') as f:
        # Сначала записываем наши известные пароли
        for p in real_passwords:
            f.write(p + '\n')
            
        # Теперь генерируем мусор, чтобы нагрузить процессор
        for _ in range(size):
            # Генерируем случайную строку длиной 8 символов
            random_pass = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
            f.write(random_pass + '\n')
            
    print(f"[+] Готово! Файл {filename} создан. Размер ~{size/100000:.1f} MB.")

if __name__ == "__main__":
    generate_big_dictionary()