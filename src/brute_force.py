import hashlib
import time
from multiprocessing import Pool, cpu_count

# Функция-воркер (должна быть вне класса для работы multiprocessing)
def check_chunk(args):
    """
    Эта функция выполняется на отдельном ядре процессора.
    Она получает кусок словаря и проверяет его.
    """
    target_hash, salt, word_chunk = args
    
    for word in word_chunk:
        word = word.strip()
        # Повторяем логику хеширования: Пароль + Соль
        attempt = word + salt
        attempt_hash = hashlib.sha256(attempt.encode()).hexdigest()
        
        if attempt_hash == target_hash:
            return word # НАШЛИ!
            
    return None

class ParallelCracker:
    def __init__(self, dictionary_path='data/dictionary.txt'):
        self.dictionary_path = dictionary_path

    def load_words(self):
        with open(self.dictionary_path, 'r', encoding='utf-8') as f:
            return f.readlines()

    def crack(self, target_hash, salt):
        print(f"[*] Запуск атаки. Доступно ядер CPU: {cpu_count()}")
        words = self.load_words()
        
        start_time = time.time()
        
        # 1. Разбиваем словарь на куски для каждого ядра
        num_cores = cpu_count()
        chunk_size = len(words) // num_cores + 1
        chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
        
        # Подготавливаем аргументы для воркеров
        tasks = [(target_hash, salt, chunk) for chunk in chunks]
        
        # 2. ПАРАЛЛЕЛЬНЫЙ ЗАПУСК
        # Pool создает процессы-воркеры
        with Pool(processes=num_cores) as pool:
            # imap_unordered запускает задачи и возвращает результат, как только кто-то закончил
            for result in pool.imap_unordered(check_chunk, tasks):
                if result:
                    pool.terminate() # Останавливаем остальные ядра, если нашли
                    end_time = time.time()
                    print(f"[!!!] ПАРОЛЬ НАЙДЕН: {result}")
                    print(f"[*] Время выполнения: {end_time - start_time:.4f} сек")
                    return result
        
        print("[-] Пароль не найден в словаре.")
        return None