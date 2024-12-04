from cryptography.hazmat.primitives import hashes
import os

L = 5 # output length in bytes

# Something to make calling hash functions more succint
def H(X):
	digest = hashes.Hash(hashes.SHA256())
	digest.update(X)
	return (digest.finalize()[0:L])

# Write a function that finds the collision and presents the values in which it occurred
def rho(h0):
	print("Hash is "+str(8*L)+" bits")

	# Your code here!!
	hi = "Nope"

	return (h0, hi)

start = os.urandom(L)
(h0, h1) = rho(start)
print(h0)
print(h1)