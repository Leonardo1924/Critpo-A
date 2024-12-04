import os 
import base64

def generate_keys():
    encryption_key = os.urandom(16) # AES-128 requires 16 bytes key
    hmac_key = os.urandom(32) # SHA-256 requires 32 bytes key

    with open('extra8/pw', 'wb') as f:
        f.write(base64.b64encode(encryption_key) + b'\n')
        f.write(base64.b64encode(hmac_key) + b'\n')

if __name__ == '__main__':
    generate_keys()