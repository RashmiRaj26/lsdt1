import numpy as np
import hashlib
import datetime
import random

def generate_invertible_cyclic_matrix(t):
    if t < 2:
        raise ValueError("t must be ≥ 2")

    gen = [0] * t
    gen[0] = 1
    if t > 2:
        gen[2] = 1
    gen[-1] = 1

    B = []
    for i in range(t):
        row = gen[-i:] + gen[:-i]
        B.append(row)

    B = np.array(B, dtype=np.uint8) % 2
    return B

def xor_bytes(*args):
    result = bytearray(args[0])
    for b in args[1:]:
        for i in range(len(result)):
            result[i] ^= b[i]
    return bytes(result)

def pad_block(block, block_size):
    pad_len = block_size - len(block)
    return block + b'\x00' * pad_len

def generate_shares(ciphertext: bytes, t: int, routing_table: dict, node_id: str):
    block_size = len(ciphertext) // t
    if len(ciphertext) % t != 0:
        block_size += 1

    blocks = [pad_block(ciphertext[i*block_size:(i+1)*block_size], block_size) for i in range(t)]

    B = generate_invertible_cyclic_matrix(t)

    bt_plus_1 = np.bitwise_xor.reduce(B, axis=0)
    B_full = np.vstack((B, bt_plus_1))

    shares = []
    timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
    paths = random.sample(routing_table[node_id], t+1)

    for i, row in enumerate(B_full):
        share = bytearray(block_size)
        for j in range(t):
            if row[j] == 1:
                for k in range(block_size):
                    share[k] ^= blocks[j][k]

        share_bytes = bytes(share)
        hash_val = hashlib.sha256((str(i+1) + str(share_bytes)).encode()).hexdigest()

        share_packet = {
            "index": i + 1,
            "share": share_bytes,
            "hash": hash_val,
            "path": [paths[i]],
            "path*": [node_id],
            "timestamp": timestamp
        }
        shares.append(share_packet)

    return shares, B_full

# ------------------------
# Example usage
# ------------------------
if __name__ == "__main__":
    ciphertext = b"This is a secret ciphertext from a sensor node."
    t = 4
    routing_table = {
        "node1": ["node2", "node3", "node4", "node5", "node6"]
    }

    shares, matrix_used = generate_shares(ciphertext, t, routing_table, "node1")

    for share in shares:
        print(f"Share {share['index']}: {share['share']}\n  Hash: {share['hash']}\n  Path: {share['path']}\n")

    print("Matrix used for encoding (over F2):\n", matrix_used)
