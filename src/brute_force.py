import hashlib
import time
from multiprocessing import Pool, cpu_count

# Worker function executed in a separate process. It must be defined at module level
def check_chunk(args):
    """
    Run inside a worker process: check each word in the provided chunk
    and return the matching password when found.
    """
    target_hash, salt, word_chunk = args
    
    for word in word_chunk:
        word = word.strip()
        # Perform the same hash operation used by the application: password + salt
        attempt = word + salt
        attempt_hash = hashlib.sha256(attempt.encode()).hexdigest()
        
        if attempt_hash == target_hash:
            return word # FOUND!
            
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
        
        # Split the dictionary into chunks so each CPU core gets roughly equal work
        num_cores = cpu_count()
        chunk_size = len(words) // num_cores + 1
        chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
        
        # Build the argument tuples that will be passed to each worker
        tasks = [(target_hash, salt, chunk) for chunk in chunks]
        # Run the workers in parallel using a process Pool. imap_unordered yields
        # results as soon as any worker finishes so we can stop early when found.
        with Pool(processes=num_cores) as pool:
            for result in pool.imap_unordered(check_chunk, tasks):
                if result:
                    pool.terminate()  # tell Pool to stop remaining workers
                    end_time = time.time()
                    print(f"[!!!] ПАРОЛЬ НАЙДЕН: {result}")
                    print(f"[*] Время выполнения: {end_time - start_time:.4f} сек")
                    return result
        
        print("[-] Пароль не найден в словаре.")
        return None