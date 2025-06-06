import socket
import oqs
import threading

HOST = '127.0.0.1'
PORT = 5555

# Setup Dilithium + Kyber keypairs
signer = oqs.Signature('Dilithium2')
sig_pub = signer.generate_keypair()

kem = oqs.KeyEncapsulation('Kyber512')
kem_pub = kem.generate_keypair()

# Connect to Peer1
s = socket.socket()
s.connect((HOST, PORT))
print("[Peer2] Connected to Peer1.")

# Receive Peer1’s public keys
peer_data = s.recv(4096)
peer_sig_pub = peer_data[:signer.details['length_public_key']]
peer_kem_pub = peer_data[signer.details['length_public_key']:]

# Send our public keys
s.sendall(sig_pub + kem_pub)

# Receive ciphertext + signature
recv = s.recv(4096)
ct_len = kem.details['length_ciphertext']
peer_ct = recv[:ct_len]
peer_sig = recv[ct_len:]

# Verify
verifier = oqs.Signature('Dilithium2')
if verifier.verify(peer_ct, peer_sig, peer_sig_pub):
    shared_secret = kem.decap_secret(peer_ct)
    print("[Peer2] Shared secret verified.")
else:
    print("[Peer2] Signature invalid!")
    exit()

# Encapsulate and sign back
ciphertext, local_secret = kem.encap_secret(peer_kem_pub)
signature = signer.sign(ciphertext)
s.sendall(ciphertext + signature)

# --- Chat using XOR with shared secret ---

def xor_encrypt(msg, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(msg)])

def receive_chat():
    while True:
        enc = s.recv(1024)
        print("Peer1:", xor_encrypt(enc, shared_secret).decode())

def send_chat():
    while True:
        msg = input()
        enc = xor_encrypt(msg.encode(), shared_secret)
        s.sendall(enc)

threading.Thread(target=receive_chat, daemon=True).start()
send_chat()
