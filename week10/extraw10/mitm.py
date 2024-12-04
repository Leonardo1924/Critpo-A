from pwn import *

# Configuration
alice_host = "localhost"   # Alice connects here (as per config_alice)
alice_port = 5075          # Port specified in config_alice

bob_host = "localhost"     # Bob listens here (as per config_bob)
bob_port = 5076            # Port specified in config_bob

# Diffie-Hellman parameters
g = 2
p = 7853799659

# MITM private keys
x_mitm = random.randint(1, p)
gx_mitm = pow(g, x_mitm, p)

y_mitm = random.randint(1, p)
gy_mitm = pow(g, y_mitm, p)

try:
    # Step 1: Listen for Alice
    print(f"[MITM] Listening for Alice on {alice_port}...")
    l_mitm = listen(alice_port)
    l_mitm.wait_for_connection()
    print("[MITM] Alice connected!")

    # Step 2: Connect to Bob
    print(f"[MITM] Connecting to Bob on {bob_host}:{bob_port}...")
    r_bob = remote(bob_host, bob_port)
    print("[MITM] Connected to Bob!")

    # Step 3: Intercept Alice's GX
    gx_from_alice = int.from_bytes(l_mitm.recvline().strip(), "little")
    print(f"[MITM] Intercepted GX from Alice: {gx_from_alice}")

    # Send MITM's GX to Bob
    r_bob.sendline(gx_mitm.to_bytes(8, "little"))
    print(f"[MITM] Sent GX to Bob: {gx_mitm}")

    # Step 4: Intercept Bob's GY
    gy_from_bob = int.from_bytes(r_bob.recvline().strip(), "little")
    print(f"[MITM] Intercepted GY from Bob: {gy_from_bob}")

    # Send MITM's GY to Alice
    l_mitm.sendline(gy_mitm.to_bytes(8, "little"))
    print(f"[MITM] Sent GY to Alice: {gy_mitm}")

    # Step 5: Calculate Shared Secrets
    shared_secret_with_alice = pow(gy_mitm, x_mitm, p)
    shared_secret_with_bob = pow(gx_mitm, y_mitm, p)

    print("[MITM] Shared secret with Alice:", shared_secret_with_alice)
    print("[MITM] Shared secret with Bob:", shared_secret_with_bob)

except Exception as e:
    print(f"[ERROR] {e}")
finally:
    # Clean up connections
    if 'l_mitm' in locals():
        l_mitm.close()
    if 'r_bob' in locals():
        r_bob.close()
    print("[MITM] Closed all connections!")
