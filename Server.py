import socket
import logging
import os
import hashlib
import json
import time
import threading
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Налаштування журналювання
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("server.log"), logging.StreamHandler()],
)


# Глобальні змінні
HOST = "127.0.0.1"
PORT = 65432
CERT_DIR = "certs"
# Глобальна змінна для зберігання оброблених міток часу
processed_timestamps = set()

def create_ca():
    """Створення кореневого CA, якщо він ще не існує."""
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)

    # Генерація CA ключів
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert_path = os.path.join(CERT_DIR, "ca_cert.pem")
    ca_key_path = os.path.join(CERT_DIR, "ca_private_key.pem")

    # Зберігання ключів
    with open(ca_key_path, "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    ca_public_key = ca_private_key.public_key()
    with open(ca_cert_path, "wb") as f:
        f.write(ca_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
    logging.info("CA ключі та сертифікат успішно створені.")


def verify_certificate(cert_bytes):
    """Перевірка сертифіката за допомогою CA ключів."""
    with open(os.path.join(CERT_DIR, "ca_cert.pem"), "rb") as f:
        ca_cert = serialization.load_pem_public_key(f.read())

    try:
        client_cert = serialization.load_pem_public_key(cert_bytes)
        ca_cert.verify(
            cert_bytes,
            client_cert.public_bytes(serialization.Encoding.PEM),
            ec.ECDSA(hashes.SHA256())
        )
        logging.info("Сертифікат підтверджено.")
        return True
    except Exception as e:
        logging.error(f"Помилка перевірки сертифіката: {e}")
        return False


def generate_ecdh_keys():
    """Генерація ключів для ECDHE."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_bytes):
    """Обчислення спільного ключа на основі ECDHE."""
    peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    session_key = HKDF(hashes.SHA256(), 32, b"handshake", b"").derive(shared_secret)
    return session_key


def encrypt_message(key, message):
    """Шифрування з AES-GCM з коректним IV."""
    iv = os.urandom(12)  # IV повинен бути рівно 12 байтів
    logging.info(f"IV (шлюз): {iv.hex()}")  # Логування IV
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    logging.info(f"Ciphertext (зашифрований текст): {ciphertext.hex()}")
    # Повертаємо IV + тег + шифрований текст
    return iv + encryptor.tag + ciphertext


def decrypt_message(key, encrypted_message):
    """Розшифрування з AES-GCM з перевіркою IV та тегу."""
    iv = encrypted_message[:12]  # Перші 12 байтів – IV
    tag = encrypted_message[12:28]  # Наступні 16 байтів – тег
    ciphertext = encrypted_message[28:]  # Решта – шифрований текст

    logging.info(f"IV отримано для розшифрування: {iv.hex()}")
    logging.info(f"Тег отримано: {tag.hex()}")
    logging.info(f"Шифрований текст: {ciphertext.hex()}")

    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        logging.info("Розшифрування пройшло успішно")
        return decrypted_data
    except Exception as e:
        logging.error(f"Помилка при розшифруванні: {e}")
        raise e


def perform_handshake(conn):
    """ECDHE handshake з обміном сертифікатами."""
    server_private_key, server_public_key = generate_ecdh_keys()
    server_pub_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    conn.sendall(len(server_pub_key_bytes).to_bytes(4, 'big') + server_pub_key_bytes)

    client_key_len = int.from_bytes(conn.recv(4), byteorder='big')
    client_pub_key_bytes = conn.recv(client_key_len)

    # Обчислення спільного секрету
    session_key = derive_shared_secret(server_private_key, client_pub_key_bytes)
    logging.info("Handshake успішний")
    return session_key


def handle_client(conn, addr):
    """Обробка клієнта."""
    try:
        logging.info(f"Підключено до клієнта: {addr}")
        session_key = perform_handshake(conn)

        if not session_key:
            logging.error("Handshake не пройшов, закриваю з'єднання")
            conn.close()
            return

        while True:
            encrypted_message = conn.recv(2048)
            if not encrypted_message:
                break

            try:
                # Розшифрування
                decrypted_message = decrypt_message(session_key, encrypted_message)
                logging.info(f"Розшифроване повідомлення: {decrypted_message.decode()}")

                # Перевірка на мітку часу
                message_text = decrypted_message.decode()
                if ':' not in message_text:
                    logging.error("Помилка: Повідомлення не містить мітку часу.")
                    conn.sendall(encrypt_message(session_key, "Помилка: Мітка часу відсутня"))
                    continue

                try:
                    # Отримання мітки часу
                    timestamp = message_text.split(':')[1].strip()

                    # Перевірка підпису
                    signature = message_text.split(':')[0].strip()
                    if verify_signature(client_public_key, message_text, signature, timestamp):
                        logging.info("Підпис підтверджено, обробляємо повідомлення")
                    else:
                        logging.error("Підпис недійсний")
                        conn.sendall(encrypt_message(session_key, "Помилка: Недійсний підпис"))
                        continue

                    # Перевірка на повторення
                    if timestamp in processed_timestamps:
                        logging.info(f"Повторення повідомлення з міткою часу: {timestamp}")
                        conn.sendall(encrypt_message(session_key, "Повторення не дозволене"))
                        continue

                    # Збереження мітки часу
                    processed_timestamps.add(timestamp)
                    logging.info(f"Мітка часу оброблена: {timestamp}")

                    # Відповідь
                    response = encrypt_message(session_key, f"Echo: {message_text}")
                    conn.sendall(response)

                except Exception as e:
                    logging.error(f"Помилка при обробці мітки часу: {e}")

            except Exception as e:
                logging.error(f"Помилка при розшифруванні даних: {e}")
    except Exception as e:
        logging.error(f"Помилка з клієнтом {addr}: {e}")
    finally:
        conn.close()
        logging.info("З'єднання з клієнтом закрито")

def verify_signature(public_key, message, signature, timestamp):
    """Перевірка цифрового підпису з міткою часу."""
    message_with_timestamp = f"{message}|{timestamp}"
    try:
        public_key.verify(
            signature,
            message_with_timestamp.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        logging.info("Підпис перевірений.")
        return True
    except Exception as e:
        logging.error(f"Помилка перевірки підпису: {e}")
        return False


def start_server():
    """Запуск сервера."""
    create_ca()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info("Сервер запущено, чекаємо на підключення...")

    while True:
        try:
            conn, addr = server_socket.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()
        except Exception as e:
            logging.error(f"Помилка при обробці підключення: {e}")


if __name__ == "__main__":
    start_server()