import hashlib
import datetime

# --- Класс "Блок" ---
# Внутри него будет логика для хранения данных и расчета хеша
class Block:
    def __init__(self, index, transactions, timestamp, previous_hash):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        # Превращаем все данные блока в одну строку и хешируем ее
        block_string = str(self.index) + str(self.timestamp) + str(self.transactions) + str(self.previous_hash)
        return hashlib.sha256(block_string.encode()).hexdigest()

# --- Класс "Блокчейн" ---
# Здесь будет храниться вся наша цепочка блоков
class Blockchain:
    def __init__(self):
        self.chain = []
        self.create_genesis_block()

    def create_genesis_block(self):
        # Создаем самый первый блок с индексом 0 и нулевым хешем предыдущего блока
        genesis_block = Block(
            index=0,
            transactions="Genesis Block",
            timestamp=str(datetime.datetime.now()),
            previous_hash="0"
        )
        self.chain.append(genesis_block)
        print("Генезис-блок создан!")

# --- Тест-драйв ---
# Создаем наш блокчейн и печатаем первый блок
my_blockchain = Blockchain()
first_block = my_blockchain.chain[0]

print("--- Наш первый блок ---")
print(f"Индекс: {first_block.index}")
print(f"Транзакции: {first_block.transactions}")
print(f"Время: {first_block.timestamp}")
print(f"Хеш предыдущего блока: {first_block.previous_hash}")
print(f"Хеш текущего блока: {first_block.hash}")
