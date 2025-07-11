import hashlib
import datetime
import json
import socket
import threading
import time
import random
import os
import sys
import sqlite3

# --- Библиотеки для криптографии ---
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256

HOST = '127.0.0.1'
DEFAULT_PORT = 65432
PEERS = []
BLOCK_REWARD = 10

# --- Класс "Транзакция" ---
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
            "timestamp": self.timestamp,
            "signature": self.signature
        }
        
    def sign_transaction(self, private_key):
        transaction_data = self.to_dict()
        transaction_data.pop("signature", None)
        transaction_hash = SHA256.new(str(transaction_data).encode())
        signer = pkcs1_15.new(private_key)
        self.signature = signer.sign(transaction_hash).hex()

    def verify_signature(self, public_key):
        if not self.signature:
            return False
        
        transaction_data = self.to_dict()
        transaction_data.pop("signature", None)
        transaction_hash = SHA256.new(str(transaction_data).encode())
        
        verifier = pkcs1_15.new(public_key)
        try:
            verifier.verify(transaction_hash, bytes.fromhex(self.signature))
            return True
        except (ValueError, TypeError):
            return False

# --- Класс "Блок" ---
class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, validator):
        self.index = index
        if isinstance(transactions, list):
            self.transactions = [tx.to_dict() if isinstance(tx, Transaction) else tx for tx in transactions] if transactions else []
        else:
            self.transactions = transactions
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
        self.db_filename = "blockchain.db"
        self.validators = {
            "Alice": 100,
            "Bob": 50,
            "Charlie": 150
        }
        self.unconfirmed_transactions = []
        
        self.setup_db()
        if not self.get_chain_length():
            self.create_genesis_block()

    def get_db_connection(self):
        return sqlite3.connect(self.db_filename)

    def setup_db(self):
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS blocks (
                    id INTEGER PRIMARY KEY,
                    data TEXT NOT NULL
                )
            """)
            conn.commit()

    def get_chain_length(self):
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM blocks")
            return cursor.fetchone()[0]

    def create_genesis_block(self):
        genesis_block = Block(
            index=0,
            transactions="Genesis Block",
            timestamp=str(datetime.datetime.now()),
            previous_hash="0",
            validator="System"
        )
        self.save_block(genesis_block)

    def save_block(self, block):
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            block_data = json.dumps(block.__dict__)
            cursor.execute("INSERT INTO blocks (id, data) VALUES (?, ?)", (block.index, block_data))
            conn.commit()

    def get_last_block(self):
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM blocks ORDER BY id DESC LIMIT 1")
            last_block_data = cursor.fetchone()
            if last_block_data:
                block_dict = json.loads(last_block_data[0])
                return Block(**block_dict)
            return None

    def get_balance(self, address):
        balance = 0
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM blocks")
            blocks_data = cursor.fetchall()
            for block_data in blocks_data:
                block_dict = json.loads(block_data[0])
                if isinstance(block_dict['transactions'], list):
                    for tx in block_dict['transactions']:
                        if tx.get("sender") == address:
                            balance -= tx.get("amount", 0)
                        if tx.get("recipient") == address:
                            balance += tx.get("amount", 0)
        return balance

    def create_new_transaction(self, sender, recipient, amount, private_key):
        new_transaction = Transaction(
            sender=sender.decode('utf-8'),
            recipient=recipient,
            amount=amount
        )
        new_transaction.sign_transaction(private_key)
        self.unconfirmed_transactions.append(new_transaction)
        print("Новая транзакция создана и добавлена в пул.")

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
        new_index = last_block.index + 1 if last_block else 0
        new_timestamp = str(datetime.datetime.now())
        new_previous_hash = last_block.hash if last_block else "0"
        
        reward_transaction = {
            "sender": "System",
            "recipient": validator,
            "amount": BLOCK_REWARD,
            "signature": None
        }

        valid_transactions = [reward_transaction]
        for tx in self.unconfirmed_transactions:
            if tx.sender == "System" or (isinstance(tx.sender, str) and self.get_balance(tx.sender) >= tx.amount):
                valid_transactions.append(tx)
            elif tx.verify_signature(RSA.import_key(tx.sender)) and self.get_balance(tx.sender) >= tx.amount:
                valid_transactions.append(tx)
            else:
                print(f"Транзакция от {tx.sender} недействительна!")
        
        self.unconfirmed_transactions = []
        
        new_block = Block(
            index=new_index,
            transactions=valid_transactions,
            timestamp=new_timestamp,
            previous_hash=new_previous_hash,
            validator=validator
        )
        self.save_block(new_block)
        print(f"Блок #{new_block.index} успешно добавлен! В нем {len(valid_transactions)} транзакций.")
        self.validators[validator] += BLOCK_REWARD

    def save_to_file(self):
        pass

    def load_from_file(self):
        return self.get_chain_length() > 0
    
    def is_valid_chain(self):
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM blocks ORDER BY id")
            blocks_data = cursor.fetchall()

            chain = []
            for b in blocks_data:
                d = json.loads(b[0])
                d.pop('hash', None)
                if isinstance(d['transactions'], str):
                    chain.append(Block(**d))
                else:
                    transactions = [Transaction(**tx) for tx in d['transactions']]
                    d['transactions'] = transactions
                    chain.append(Block(**d))

            for i in range(1, len(chain)):
                current_block = chain[i]
                previous_block = chain[i-1]
                
                if current_block.hash != current_block.calculate_hash():
                    return False
                
                if current_block.previous_hash != previous_block.hash:
                    return False
        return True

    def save_synced_chain(self, received_chain_dicts):
        with self.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM blocks")
            for d in received_chain_dicts:
                d.pop('hash', None)
                block = Block(**d)
                self.save_block(block)
            conn.commit()


# --- Класс для P2P узла (обновлен) ---
class P2PNode:
    def __init__(self, port, peers):
        self.port = port
        self.peers = peers
        self.blockchain = Blockchain()
        self.node_server = None
        self.is_running = True
        
    def handle_client(self, conn, addr):
        try:
            data = conn.recv(4096)
            if data:
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'sync_request':
                    self.send_blockchain_to_peer(conn)
                elif message['type'] == 'new_transactions':
                    print("Получены новые транзакции. Добавляю в пул.")
                    self.add_received_transactions(message['payload'])
                elif message['type'] == 'new_block':
                    print("Получен новый блок. Проверяю и добавляю.")
                    self.add_received_block(message['payload'])
        except Exception as e:
            print(f"Ошибка при обработке запроса: {e}")
        finally:
            conn.close()

    def add_received_transactions(self, transactions):
        for tx_dict in transactions:
            tx = Transaction(**tx_dict)
            self.blockchain.unconfirmed_transactions.append(tx)
            print("Новые транзакции добавлены в пул.")
    
    def add_received_block(self, block_data):
        current_chain_len = self.blockchain.get_chain_length()
        if block_data['index'] >= current_chain_len:
            block = Block(**block_data)
            self.blockchain.save_block(block)
            print(f"Новый блок #{block.index} успешно добавлен в мою цепочку.")
        else:
            print(f"Полученный блок #{block_data['index']} уже существует.")

    def start_server(self):
        self.node_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.node_server.bind((HOST, self.port))
        self.node_server.listen(5)
        print(f"Сервер слушает на {HOST}:{self.port}")
        while self.is_running:
            try:
                conn, addr = self.node_server.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()
            except socket.timeout:
                continue

    def connect_to_peers(self):
        for peer in self.peers:
            peer_host, peer_port = peer.split(':')
            peer_port = int(peer_port)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer_host, peer_port))
                    request = {'type': 'sync_request'}
                    s.sendall(json.dumps(request).encode('utf-8'))
                    
                    data = s.recv(4096)
                    if data:
                        received_chain_json = data.decode('utf-8')
                        received_dicts = json.loads(received_chain_json)
                        self.blockchain.save_synced_chain(received_dicts)
                        print("Моя цепочка успешно обновлена!")
            except ConnectionRefusedError:
                print(f"Ошибка: Не удалось подключиться к {peer}. Узел недоступен.")
            except Exception as e:
                print(f"Произошла ошибка при подключении: {e}")

    def sync_chain(self, received_chain_json):
        # Этот метод больше не используется
        pass
    
    def send_blockchain_to_peer(self, conn):
        with self.blockchain.get_db_connection() as db_conn:
            cursor = db_conn.cursor()
            cursor.execute("SELECT data FROM blocks ORDER BY id")
            blocks_data = cursor.fetchall()
            blockchain_dicts = [json.loads(b[0]) for b in blocks_data]
            blockchain_json = json.dumps(blockchain_dicts)
            conn.sendall(blockchain_json.encode('utf-8'))

    def broadcast_message(self, message):
        for peer in self.peers:
            peer_host, peer_port = peer.split(':')
            peer_port = int(peer_port)
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((peer_host, peer_port))
                    s.sendall(json.dumps(message).encode('utf-8'))
            except ConnectionRefusedError:
                print(f"Не удалось отправить сообщение {peer}.")

    def run(self):
        server_thread = threading.Thread(target=self.start_server)
        server_thread.daemon = True
        server_thread.start()
        
        main_thread = threading.Thread(target=self.main_loop)
        main_thread.start()

    def main_loop(self):
        while self.is_running:
            choice = input("\nВведите 'sync' для синхронизации, 'n' для нового блока, 'v' для валидации, 't' для транзакции, 'b' для баланса, или 'exit' для выхода: ").lower()
            if choice == 'sync':
                self.connect_to_peers()
            elif choice == 'n':
                validator = self.blockchain.select_validator()
                if validator:
                    self.blockchain.add_block(validator)
                    self.broadcast_message({'type': 'new_block', 'payload': self.blockchain.get_last_block().__dict__})
            elif choice == 'v':
                if self.blockchain.is_valid_chain():
                    print("Цепочка блоков верна и не повреждена.")
                else:
                    print("ВНИМАНИЕ: Цепочка блоков повреждена!")
            elif choice == 't':
                key = RSA.generate(2048)
                private_key = key
                public_key = key.publickey()
                
                self.blockchain.create_new_transaction(
                    sender=public_key.export_key(),
                    recipient="Bob's_Public_Key",
                    amount=10,
                    private_key=private_key
                )
                
                transactions_to_broadcast = [tx.to_dict() for tx in self.blockchain.unconfirmed_transactions]
                self.broadcast_message({'type': 'new_transactions', 'payload': transactions_to_broadcast})
                
            elif choice == 'b':
                address = input("Введите адрес для проверки баланса: ")
                balance = self.blockchain.get_balance(address)
                print(f"Текущий баланс: {balance} монет.")

            elif choice == 'exit':
                self.is_running = False
                sys.exit()
            
            self.blockchain.conn.close()
            time.sleep(1)

if __name__ == "__main__":
    node_port = int(input(f"Введите порт для этого узла (например, {DEFAULT_PORT}): "))
    peer_list = input("Введите список пиров через запятую (например: 127.0.0.1:65433,127.0.0.1:65434): ")
    PEERS = peer_list.split(',') if peer_list else []
    node = P2PNode(node_port, PEERS)
    node.run()
