import hashlib
import datetime
import json
import socket
import threading
import time
import random

HOST = '127.0.0.1'
PORT = 65432
PEERS = [] 

# --- Класс "Блок" ---
class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, validator):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.validator = validator
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_string = json.dumps(self.__dict__, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

# --- Класс "Блокчейн" (обновлен) ---
class Blockchain:
    def __init__(self):
        self.chain = []
        self.validators = {
            "Alice": 100,
            "Bob": 50,
            "Charlie": 150
        }
        self.unconfirmed_transactions = []
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = Block(
            index=0,
            transactions="Genesis Block",
            timestamp=str(datetime.datetime.now()),
            previous_hash="0",
            validator="System"
        )
        self.chain.append(genesis_block)

    def get_last_block(self):
        return self.chain[-1]
    
    def create_new_transaction(self, sender, recipient, amount):
        transaction = {
            "sender": sender,
            "recipient": recipient,
            "amount": amount
        }
        self.unconfirmed_transactions.append(transaction)
        print("Новая транзакция добавлена в пул.")

    def select_validator(self):
        total_stake = sum(self.validators.values())
        choice = random.uniform(0, total_stake)
        current_sum = 0
        for validator, stake in self.validators.items():
            current_sum += stake
            if choice <= current_sum:
                return validator
        return None

    def add_block(self, validator):
        last_block = self.get_last_block()
        new_index = last_block.index + 1
        new_timestamp = str(datetime.datetime.now())
        new_previous_hash = last_block.hash
        
        transactions_to_add = list(self.unconfirmed_transactions)
        self.unconfirmed_transactions = []

        new_block = Block(
            index=new_index,
            transactions=transactions_to_add,
            timestamp=new_timestamp,
            previous_hash=new_previous_hash,
            validator=validator
        )
        self.chain.append(new_block)
        print(f"Блок #{new_block.index} успешно добавлен! В нем {len(transactions_to_add)} транзакций.")
        self.validators[validator] += 1
        
# --- Cетевая логика (обновлена) ---
my_blockchain = Blockchain()

def handle_sync_request(conn):
    """Отправляет клиенту полную копию нашего блокчейна."""
    try:
        print("Получен запрос на синхронизацию.")
        blockchain_json = json.dumps([vars(block) for block in my_blockchain.chain])
        conn.sendall(blockchain_json.encode('utf-8'))
        print("Моя копия блокчейна отправлена.")
    finally:
        conn.close()

def start_server():
    """Запускает узел-сервер."""
    print("Запуск узла в режиме сервера...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Сервер слушает на {HOST}:{PORT}")
        conn, addr = s.accept()
        handle_sync_request(conn)

def sync_with_peer():
    """Узел-клиент запрашивает блокчейн у другого узла."""
    print("Запрос на синхронизацию...")
    time.sleep(2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((HOST, PORT))
            data = s.recv(1024 * 10)
            if data:
                received_chain_json = data.decode('utf-8')
                received_chain = [Block(**d) for d in json.loads(received_chain_json)]
                
                # Обновляем свою цепочку, если полученная длиннее
                if len(received_chain) > len(my_blockchain.chain):
                    my_blockchain.chain = received_chain
                    print("Моя цепочка успешно обновлена!")
                else:
                    print("Моя цепочка уже актуальна.")
        except ConnectionRefusedError:
            print("Ошибка: не удалось подключиться к другому узлу.")

def main():
    mode = input("Запустить как сервер (s) или клиент (c)? ").lower()
    if mode == 's':
        # Создаем пару блоков, чтобы цепочка была длиннее
        my_blockchain.add_block(my_blockchain.select_validator())
        my_blockchain.add_block(my_blockchain.select_validator())
        start_server()
    elif mode == 'c':
        print("Моя локальная цепочка:")
        print(f"Длина: {len(my_blockchain.chain)}")
        sync_with_peer()
        print("\nПосле синхронизации:")
        print(f"Длина: {len(my_blockchain.chain)}")
    else:
        print("Неверный выбор.")

if __name__ == "__main__":
    main()
