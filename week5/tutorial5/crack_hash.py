from cryptography.hazmat.primitives import hashes
from binascii import hexlify, unhexlify
import os
import numpy as np

# The most common passwords of 2019.
passwds = ['123456','123456789','qwerty','password','1234567','12345678','12345','iloveyou','111111','123123','abc123','qwerty123','1q2w3e4r','admin','qwertyuiop','654321','555555','lovely','7777777','welcome']

### Non-salt version

# Get their hex versions
hex_passwds = []
for pwd in passwds:
	hex_passwds.append(hexlify(pwd.encode()))

# Hash all the passwords
hlist = []
for pwd in hex_passwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	hlist.append(hexlify(digest.finalize()))

#### Salt version

# Random salt of 1 byte
salt_passwds = []
salt = os.urandom(1)

# The same passwords, but now with the random salt prepended
for pwd in hex_passwds:
	salt_passwds.append(salt+pwd)

# Hash all salted passwords
shlist = []
for pwd in salt_passwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	shlist.append(hexlify(digest.finalize()))


### Lets mix it up
# numpy 1.5.0 required!

mixed_hlist = np.random.permutation(hlist)
mixed_shlist = np.random.permutation(shlist)


### Exercise 1 - Crack unsalted hashes
# You can use mixed_hlist, hex_passwds and hlist
# Produce a list cracked_pwds that has the list of hex passwords in the correct sequence

cracked_pwds = []

for mixed_hash in mixed_hlist:
    for pwd in hex_passwds:
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pwd)
        if mixed_hash == hexlify(digest.finalize()):
            cracked_pwds.append(pwd)
            break


# Lets see if your list is correct
i = 0
for pwd in cracked_pwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	if (mixed_hlist[i] == hexlify(digest.finalize())):
		print(i, "Check")
	i += 1


### Exercise 2 - Crack salted hashes
# You can use mixed_shlist, hex_passwds and hlist
# You can't use shlist and salt!!
# Produce a list cracked_spwds that has the list of hex passwords in the correct sequence

cracked_spwds = []

# Try all possible single-byte salts (256 possibilities)
for mixed_salted_hash in mixed_shlist:
    found = False
    for pwd in hex_passwds:
        for salt_guess in range(256):  # Try every possible salt (1-byte range from 0x00 to 0xFF)
            salt = bytes([salt_guess])  # Convert the salt guess to a single byte
            salted_pwd = salt + pwd     # Prepend the salt to the password
            digest = hashes.Hash(hashes.SHA256())
            digest.update(salted_pwd)
            if mixed_salted_hash == hexlify(digest.finalize()):  # Compare the salted hash
                cracked_spwds.append(salted_pwd)  # Store the salted password directly
                found = True
                break  # Stop once we find a match for this hash
        if found:
            break  # Stop once we find a match for this hash

i = 0
for pwd in cracked_spwds:
	digest = hashes.Hash(hashes.SHA256())
	digest.update(pwd)
	if (mixed_shlist[i] == hexlify(digest.finalize())):
		print(i, "Check")
	i += 1
