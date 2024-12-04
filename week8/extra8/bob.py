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
    expected_sequence_number = 1

    responses = [
        "Hello Alice",
        "Me too. Same time, same place?"
    ]

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            while True:
                # Receive message
                data = conn.recv(1024)
                if not data:
                    break
                encrypted_message = data[:-32]
                received_hmac = data[-32:]
                if verify_hmac(hmac_key, encrypted_message, received_hmac):
                    decrypted_message = decrypt_message(encryption_key, encrypted_message)
                    received_sequence_number, received_message = decrypted_message.decode().split(':', 1)
                    if int(received_sequence_number) == expected_sequence_number:
                        print(f"Received: {received_message}")
                        expected_sequence_number += 1
                        
                        # Send response if there are any left
                        if responses:
                            response = responses.pop(0)
                            response_message = f"{expected_sequence_number}:{response}".encode()
                            encrypted_response = encrypt_message(encryption_key, response_message)
                            response_hmac = create_hmac(hmac_key, encrypted_response)
                            conn.sendall(encrypted_response + response_hmac)
                            print(f"Sent: {response_message}")
                        else:
                            print("No more responses to send.")
                            print("Simulation concluded with success")
                            break
                    else:
                        print(f"Sequence number mismatch: expected {expected_sequence_number}, got {received_sequence_number}")
                        break
                else:
                    print("HMAC verification failed")
                    break
                
                # Wait for 2 seconds before processing the next message
                time.sleep(5)