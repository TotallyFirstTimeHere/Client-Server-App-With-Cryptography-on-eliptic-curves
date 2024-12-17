import socket
import logging
import os
import time

from cryptography.hazmat.primitives._serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Налаштування журналювання
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("client.log"), logging.StreamHandler()],
)

# Глобальні змінні
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 65432
CERT_DIR = "certs"
client_private_key = None  # Це глобальна змінна для приватного ключа клієнта
client_public_key = None   # Це глобальна змінна для публічного ключа клієнта


def generate_client_ca():
    """Генерація кореневого сертифіката (CA) для клієнта."""
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)

    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert_path = os.path.join(CERT_DIR, "client_ca_cert.pem")
    ca_key_path = os.path.join(CERT_DIR, "client_ca_private_key.pem")

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

    logging.info("CA створено успішно")


def create_certificate():
    """Створення сертифіката для клієнта."""
    global client_private_key, client_public_key  # Позначаємо, що будемо використовувати глобальні змінні
    client_private_key = ec.generate_private_key(ec.SECP256R1())  # Генеруємо приватний ключ
    client_public_key = client_private_key.public_key()  # Отримуємо публічний ключ
    cert_path = os.path.join(CERT_DIR, "client_cert.pem")
    key_path = os.path.join(CERT_DIR, "client_private_key.pem")

    # Зберігання ключів
    with open(key_path, "wb") as f:
        f.write(client_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_path, "wb") as f:
        f.write(client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    logging.info("Сертифікат та ключ успішно створені")


def verify_server_certificate(cert_bytes):
    """Перевірка отриманого сертифіката сервера."""
    try:
        with open(os.path.join(CERT_DIR, "client_ca_cert.pem"), "rb") as f:
            ca_public_key = serialization.load_pem_public_key(f.read())

        server_cert = serialization.load_pem_public_key(cert_bytes)

        # Перевірка підпису
        ca_public_key.verify(
            server_cert.public_bytes(Encoding.PEM),
            cert_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        logging.info("Сертифікат сервера підтверджено.")
        return True
    except Exception as e:
        logging.error(f"Сертифікат сервера недійсний: {e}")
        return False


def generate_ecdh_keys():
    """Генерація ключів для ECDHE."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_secret(private_key, peer_public_bytes):
    """Обчислення спільного секрету на основі ECDHE."""
    peer_public_key = serialization.load_pem_public_key(peer_public_bytes)
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    session_key = HKDF(hashes.SHA256(), 32, b"handshake", b"").derive(shared_secret)
    return session_key


def encrypt_message(key, message):
    """Шифрування з AES-GCM."""
    iv = os.urandom(12)  # IV повинен бути рівно 12 байтів
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    # Повертаємо IV + тег + шифрований текст
    return iv + encryptor.tag + ciphertext


def decrypt_message(key, encrypted_message):
    """Розшифрування з AES-GCM."""
    iv = encrypted_message[:12]  # Перші 12 байтів – IV
    tag = encrypted_message[12:28]  # Наступні 16 байтів – тег
    ciphertext = encrypted_message[28:]  # Решта – шифрований текст

    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except Exception as e:
        logging.error(f"Помилка при розшифруванні: {e}")
        raise e


def perform_handshake(conn):
    """ECDHE handshake з сервером."""
    client_private_key, client_public_key = generate_ecdh_keys()
    client_pub_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    conn.sendall(len(client_pub_key_bytes).to_bytes(4, 'big') + client_pub_key_bytes)

    server_key_len = int.from_bytes(conn.recv(4), byteorder='big')
    server_pub_key_bytes = conn.recv(server_key_len)

    session_key = derive_shared_secret(client_private_key, server_pub_key_bytes)
    logging.info("Handshake успішний")
    return session_key


def client():
    """Клієнтська програма."""
    generate_client_ca()
    create_certificate()

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    session_key = perform_handshake(client_socket)

    while True:
        message = input("Введіть повідомлення для відправлення серверу: ")

        if not message:
            break

        encrypted_message = encrypt_message(session_key, message)
        client_socket.sendall(encrypted_message)

        # Отримання відповіді від сервера
        encrypted_response = client_socket.recv(2048)
        decrypted_response = decrypt_message(session_key, encrypted_response)
        print(f"Відповідь сервера: {decrypted_response.decode()}")


if __name__ == "__main__":
    client()