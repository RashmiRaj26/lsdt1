import numpy as np
import hashlib
import datetime
import random
from Message_encryption.invertible_matrix import generate_invertible_cyclic_matrix  


def xor_bytes(*args):
    result = bytearray(args[0])
    for b in args[1:]:
        for i in range(len(result)):
            result[i] ^= b[i]
    return bytes(result)


def pad_block(block, block_size):
    block = block.encode() if isinstance(block, str) else block
    pad_len = block_size - len(block)
    return block + b'\x00' * pad_len


def generate_shares(ciphertext: bytes, t: int, routing_table: dict, node_id: str):
    total_len = len(ciphertext)
    block_size = total_len // t
    if total_len % t != 0:
        block_size += 1

    # Divide ciphertext into t blocks of equal size with padding
    blocks = [
        pad_block(ciphertext[i * block_size: (i + 1) * block_size], block_size)
        for i in range(t)
    ]

    # Generate t linearly independent vectors on F2 (invertible matrix)
    B = generate_invertible_cyclic_matrix(t)

    # Generate bt+1 = b1 ⊕ b2 ⊕ ... ⊕ bt
    bt_plus_1 = np.bitwise_xor.reduce(B, axis=0)

    # Full matrix with t+1 linearly independent vectors
    B_full = np.vstack((B, bt_plus_1))

    # Select t+1 routing paths randomly
    paths = random.sample(routing_table[node_id], t + 1)

    # Timestamp for all shares
    timestamp = datetime.datetime.utcnow().isoformat() + 'Z'

    shares = []
    for i, row in enumerate(B_full):
        # XOR block selection based on matrix row
        share = bytearray(block_size)
        for j in range(t):
            if row[j] == 1:
                for k in range(block_size):
                    share[k] ^= blocks[j][k]

        share_bytes = bytes(share)
        hash_val = hashlib.sha256((str(i + 1) + str(share_bytes)).encode()).hexdigest()

        share_packet = {
            "index": i + 1,
            "share": share_bytes,
            "hash": hash_val,
            "path": [paths[i]],     # pathi ∈ Tw
            "path*": [node_id],     # IDw
            "timestamp": timestamp, # TS
            "block_size": block_size,
            "total_len": total_len
        }
        shares.append(share_packet)

    return shares
