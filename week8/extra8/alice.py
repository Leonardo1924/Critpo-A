import socket
import base64
import os
import hmac
import hashlib
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def read_keys():
    with open('pw', 'rb') as f:
        encryption_key = base64.b64decode(f.readline().strip())
        hmac_key = base64.b64decode(f.readline().strip())
    return encryption_key, hmac_key

def encrypt_message(key, plaintext):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return nonce + ciphertext

def create_hmac(key, message):
    return hmac.new(key, message, hashlib.sha256).digest()

def decrypt_message(key, ciphertext):
    nonce = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext

def verify_hmac(key, message, received_hmac):
    expected_hmac = hmac.new(key, message, hashlib.sha256).digest()
    return hmac.compare_digest(expected_hmac, received_hmac)

if __name__ == "__main__":
    encryption_key, hmac_key = read_keys()
    sequence_number = 1

    messages = [
        "Hello Bob",
        "I would like to have dinner",
        "Sure!"
    ]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))
        
        for message in messages:
            # Send message
            message_to_send = f"{sequence_number}:{message}".encode()
            encrypted_message = encrypt_message(encryption_key, message_to_send)
            message_hmac = create_hmac(hmac_key, encrypted_message)
            s.sendall(encrypted_message + message_hmac)
            print(f"Sent: {message_to_send}")
            
            # Receive response
            data = s.recv(1024)
            if not data:
                print("Connection closed by Bob")
                break
            encrypted_message = data[:-32]
            received_hmac = data[-32:]
            if verify_hmac(hmac_key, encrypted_message, received_hmac):
                decrypted_message = decrypt_message(encryption_key, encrypted_message)
                received_sequence_number, received_message = decrypted_message.decode().split(':', 1)
                if int(received_sequence_number) == sequence_number + 1:
                    print(f"Received: {received_message}")
                    sequence_number += 1
                else:
                    print(f"Sequence number mismatch: expected {sequence_number + 1}, got {received_sequence_number}")
                    break
            else:
                print("HMAC verification failed")
                break
            time.sleep(5)
        
        print("Simulation concluded with success")