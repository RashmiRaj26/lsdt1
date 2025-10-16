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
    blocks = [
        pad_block(ciphertext[i * block_size: (i + 1) * block_size], block_size)
        for i in range(t)
    ]
    B = generate_invertible_cyclic_matrix(t)
    bt_plus_1 = np.bitwise_xor.reduce(B, axis=0)
    share_packet_t_plus_1=ciphertext
    B_full = np.vstack((B, bt_plus_1))
    # Choose t+1 distinct paths if available; otherwise allow sampling with replacement
    candidates = list(routing_table.get(node_id, []))
    needed = t + 1
    if not candidates:
        raise ValueError(f"No routing candidates available for node_id={node_id}")
    if len(candidates) >= needed:
        paths = random.sample(candidates, needed)
    else:
        # Not enough unique candidates: sample and allow duplicates to reach required count
        paths = candidates.copy()
        while len(paths) < needed:
            paths.append(random.choice(candidates))
    timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
    shares = []
    for i, row in enumerate(B_full):
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
            "path": [paths[i]], 
            "path*": [node_id],    
            "timestamp": timestamp,
            "block_size": block_size,
            "total_len": total_len
        }
        shares.append(share_packet)   
    for share in shares:
        print(f"Share {share['index']}: {share['share']}\n  Hash: {share['hash']}\n  Path: {share['path']}\n")
    shares.append(share_packet_t_plus_1)
    return shares
