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

# Bind and listen for peer
s = socket.socket()
s.bind((HOST, PORT))
s.listen(1)
print("[Peer1] Waiting for Peer2...")
conn, _ = s.accept()
print("[Peer1] Peer2 connected.")

# Send our Dilithium and Kyber public keys
conn.sendall(sig_pub + kem_pub)

# Receive Peer2’s keys
peer_data = conn.recv(4096)
peer_sig_pub = peer_data[:signer.details['length_public_key']]
peer_kem_pub = peer_data[signer.details['length_public_key']:]

# Encapsulate + sign
ciphertext, shared_secret = kem.encap_secret(peer_kem_pub)
signature = signer.sign(ciphertext)

# Send ciphertext + signature
conn.sendall(ciphertext + signature)

# Receive their ciphertext + signature
recv = conn.recv(4096)
ct_len = kem.details['length_ciphertext']
peer_ct = recv[:ct_len]
peer_sig = recv[ct_len:]

# Verify
verifier = oqs.Signature('Dilithium2')
if verifier.verify(peer_ct, peer_sig, peer_sig_pub):
    peer_secret = kem.decap_secret(peer_ct)
    print("[Peer1] Shared secret verified.")
else:
    print("[Peer1] Signature failed!")
    exit()

# --- Chat using XOR with shared secret (demo) ---

def xor_encrypt(msg, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(msg)])

def receive_chat():
    while True:
        enc = conn.recv(1024)
        print("Peer2:", xor_encrypt(enc, shared_secret).decode())

def send_chat():
    while True:
        msg = input()
        enc = xor_encrypt(msg.encode(), shared_secret)
        conn.sendall(enc)

threading.Thread(target=receive_chat, daemon=True).start()
send_chat()
