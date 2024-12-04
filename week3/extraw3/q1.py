import ciphersuite_aesnotrand as ciphersuite
from binascii import hexlify, unhexlify

key = ciphersuite.gen()
msg = 'Attack at dawn!!'
cph = ciphersuite.enc(key, bytearray(msg,'ascii'))

f = open("weak_ciphertext", "wb")
f.write(cph)
f.close()

## 
# Extend me to
# 1 - Read ciphertext
# 2 - Guess the key used
# 3 - Test the decryption
##