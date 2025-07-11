import hashlib
import datetime
import json
import socket
import threading
import time
import random
import os

# --- Библиотеки для криптографии ---
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

HOST = '127.0.0.1'
PORT = 65432
PEERS = ['127.0.0.1:65433', '127.0.0.1:65434']

# --- Класс "Транзакция" (НОВЫЙ) ---
class Transaction:
    def __init__(self, sender, recipient, amount, signature=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.signature = signature
        
    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "timestamp": self.timestamp
        }
        
    def sign_transaction(self, private_key):
        # Превращаем данные в хеш и подписываем его
        transaction_hash = SHA256.new(str(self.to_dict()).encode())
        signer = pkcs1_15.new(private_key)
        self.signature = signer.sign(transaction_hash).hex()

    def verify_signature(self, public_key):
        if not self.signature:
            return False
        
        # Проверяем подпись
        transaction_hash = SHA256.new(str(self.to_dict()).encode())
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(transaction_hash, bytes.fromhex(self.signature))
            return True
        except (ValueError, TypeError):
            return False

# --- Класс "Блок" (обновлен) ---
class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, validator):
        self.index = index
        # Сохраняем транзакции в виде словарей
        self.transactions = [tx.to_dict() for tx in transactions] if transactions else []
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.validator = validator
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_data = self.__dict__.copy()
        block_data.pop("hash", None)
        block_string = json.dumps(block_data, sort_keys=True)
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
        self.filename = "blockchain.json"
        
        if not self.load_from_file():
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
    
    def create_new_transaction(self, sender, recipient, amount, signature):
        # Проверяем, что подпись транзакции верна, прежде чем добавлять ее в пул
        public_key = RSA.import_key(sender)
        if Transaction(sender, recipient, amount, signature).verify_signature(public_key):
            transaction = {
                "sender": sender,
                "recipient": recipient,
                "amount": amount,
                "signature": signature
            }
            self.unconfirmed_transactions.append(transaction)
            print("Новая транзакция добавлена в пул.")
        else:
            print("ОШИБКА: Недействительная подпись транзакции!")

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
        
        # Теперь берем транзакции из пула и добавляем их в новый блок
        transactions_to_add = [Transaction(**tx) for tx in self.unconfirmed_transactions]
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

    def save_to_file(self):
        with open(self.filename, 'w') as f:
            blockchain_dicts = [block.__dict__ for block in self.chain]
            json.dump(blockchain_dicts, f, indent=4)
        print("Блокчейн успешно сохранен.")

    def load_from_file(self):
        if os.path.exists(self.filename):
            with open(self.filename, 'r') as f:
                try:
                    loaded_chain = json.load(f)
                    self.chain = []
                    for d in loaded_chain:
                        d.pop('hash', None)
                        self.chain.append(Block(**d))
                    print("Блокчейн успешно загружен из файла.")
                    return True
                except json.JSONDecodeError:
                    print("Ошибка загрузки файла, создаем новый блокчейн.")
        return False
    
    def is_valid_chain(self):
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True

# --- Cетевая логика (обновлена) ---
my_blockchain = Blockchain()

def handle_sync_request(conn):
    try:
        print("Получен запрос на синхронизацию.")
        blockchain_dicts = [block.__dict__ for block in my_blockchain.chain]
        blockchain_json = json.dumps(blockchain_dicts)
        conn.sendall(blockchain_json.encode('utf-8'))
        print("Моя копия блокчейна отправлена.")
    finally:
        conn.close()

def start_server(port):
    print(f"Запуск узла в режиме сервера на порту {port}...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, port))
        s.listen()
        print(f"Сервер слушает на {HOST}:{port}")
        conn, addr = s.accept()
        handle_sync_request(conn)

def sync_with_peer(peer_host, peer_port):
    print(f"Запрос на синхронизацию с {peer_host}:{peer_port}...")
    time.sleep(2)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((peer_host, peer_port))
            data = s.recv(1024 * 10)
            if data:
                received_chain_json = data.decode('utf-8')
                received_dicts = json.loads(received_chain_json)
                
                received_chain = []
                for d in received_dicts:
                    d.pop('hash', None)
                    received_chain.append(Block(**d))
                
                if len(received_chain) > len(my_blockchain.chain):
                    my_blockchain.chain = received_chain
                    print("Моя цепочка успешно обновлена!")
                else:
                    print("Моя цепочка уже актуальна.")
        except ConnectionRefusedError:
            print("Ошибка: не удалось подключиться к другому узлу.")
        except Exception as e:
            print(f"Произошла ошибка при синхронизации: {e}")

def main():
    mode = input("Запустить как сервер (s), клиент (c), добавить новый блок (n), проверить цепочку (v) или создать транзакцию (t)? ").lower()
    if mode == 's':
        start_server(PORT)
    elif mode == 'c':
        peer_host = input("Введите IP-адрес узла для подключения: ")
        peer_port = int(input("Введите порт узла: "))
        sync_with_peer(peer_host, peer_port)
    elif mode == 'n':
        my_blockchain.add_block(my_blockchain.select_validator())
    elif mode == 'v':
        if my_blockchain.is_valid_chain():
            print("Цепочка блоков верна и не повреждена.")
        else:
            print("ВНИМАНИЕ: Цепочка блоков повреждена!")
    elif mode == 't':
        # Создаем ключи для демонстрации
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        # Создаем транзакцию
        new_transaction = Transaction(
            sender=public_key.decode('utf-8'),
            recipient="Bob's_Public_Key",
            amount=10
        )
        
        # Подписываем ее приватным ключом
        new_transaction.sign_transaction(key)
        
        # Добавляем в пул
        my_blockchain.unconfirmed_transactions.append(new_transaction.to_dict())
        print("Транзакция создана и подписана. Теперь ее можно включить в блок.")
    else:
        print("Неверный выбор.")
    
    my_blockchain.save_to_file()

if __name__ == "__main__":
    my_blockchain = Blockchain()
    main()
