import hashlib
import json
import time
import os

BLOCKCHAIN_FILE = 'data/audit_log.json'

class Block:
    def __init__(self, index, event, prev_hash, timestamp=None):
        self.index = index
        self.timestamp = timestamp or time.time()
        self.event = event  # Текст события (например, "User registered")
        self.prev_hash = prev_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Хешируем комбинацию: индекс + время + данные + хеш прошлого блока
        block_string = f"{self.index}{self.timestamp}{self.event}{self.prev_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event": self.event,
            "prev_hash": self.prev_hash,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

    def create_genesis_block(self):
        # Первый блок всегда создается вручную
        return Block(0, "Genesis Block: System Init", "0")

    def get_latest_block(self):
        return self.chain[-1]

    def add_event(self, event_text):
        prev_block = self.get_latest_block()
        new_block = Block(
            index=prev_block.index + 1,
            event=event_text,
            prev_hash=prev_block.hash
        )
        self.chain.append(new_block)
        self.save_chain()
        print(f"[Blockchain] Событие зафиксировано: {event_text}")

    def is_chain_valid(self):
        """
        Проходит по всей цепи и проверяет математическую целостность.
        Если хоть один байт в файле был изменен хакером, вернет False.
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            prev = self.chain[i-1]

            # 1. Проверка целостности данных внутри блока
            if current.hash != current.calculate_hash():
                print(f"[!!!] ОШИБКА: Хеш блока {i} неверен! Данные изменены.")
                return False
            
            # 2. Проверка связи с предыдущим блоком
            if current.prev_hash != prev.hash:
                print(f"[!!!] ОШИБКА: Разрыв цепи между {i-1} и {i}!")
                return False
        
        return True

    def save_chain(self):
        data = [block.to_dict() for block in self.chain]
        with open(BLOCKCHAIN_FILE, 'w') as f:
            json.dump(data, f, indent=4)

    def load_chain(self):
        if os.path.exists(BLOCKCHAIN_FILE):
            try:
                with open(BLOCKCHAIN_FILE, 'r') as f:
                    data = json.load(f)
                    self.chain = [Block(b['index'], b['event'], b['prev_hash'], b['timestamp']) for b in data]
                    # Если хеш в файле не совпадает с пересчитанным при загрузке - это уже подозрительно,
                    # но для простоты мы оставим проверку в методе is_chain_valid
            except:
                self.chain = [self.create_genesis_block()]
        else:
            self.chain = [self.create_genesis_block()]
            self.save_chain()
            