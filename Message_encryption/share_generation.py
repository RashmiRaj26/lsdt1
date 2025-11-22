# # import numpy as np
# # import hashlib
# # import datetime
# # import random
# # from Message_encryption.invertible_matrix import generate_invertible_cyclic_matrix  

# # def xor_bytes(*args):
# #     result = bytearray(args[0])
# #     for b in args[1:]:
# #         for i in range(len(result)):
# #             result[i] ^= b[i]
# #     return bytes(result)


# # def pad_block(block, block_size):
# #     block = block.encode() if isinstance(block, str) else block
# #     pad_len = block_size - len(block)
# #     return block + b'\x00' * pad_len


# # def generate_shares(ciphertext: bytes, t: int, routing_table: dict, node_id: str):
# #     total_len = len(ciphertext)
# #     block_size = total_len // t
# #     if total_len % t != 0:
# #         block_size += 1
# #     blocks = [
# #         pad_block(ciphertext[i * block_size: (i + 1) * block_size], block_size)
# #         for i in range(t)
# #     ]
# #     B = generate_invertible_cyclic_matrix(t)
# #     bt_plus_1 = np.bitwise_xor.reduce(B, axis=0)
# #     share_packet_t_plus_1=ciphertext
# #     B_full = np.vstack((B, bt_plus_1))
# #     # Choose t+1 distinct paths if available; otherwise allow sampling with replacement
# #     candidates = list(routing_table.get(node_id, []))
# #     needed = t + 1
# #     if not candidates:
# #         raise ValueError(f"No routing candidates available for node_id={node_id}")
# #     if len(candidates) >= needed:
# #         paths = random.sample(candidates, needed)
# #     else:
# #         # Not enough unique candidates: sample and allow duplicates to reach required count
# #         paths = candidates.copy()
# #         while len(paths) < needed:
# #             paths.append(random.choice(candidates))
# #     timestamp = datetime.datetime.utcnow().isoformat() + 'Z'
# #     shares = []
# #     for i, row in enumerate(B_full):
# #         share = bytearray(block_size)
# #         for j in range(t):
# #             if row[j] == 1:
# #                 for k in range(block_size):
# #                     share[k] ^= blocks[j][k]

# #         share_bytes = bytes(share)
# #         hash_val = hashlib.sha256((str(i + 1) + str(share_bytes)).encode()).hexdigest()

# #         share_packet = {
# #             "index": i + 1,
# #             "share": share_bytes,
# #             "hash": hash_val,
# #             "path": [paths[i]], 
# #             "path*": [node_id],    
# #             "timestamp": timestamp,
# #             "block_size": block_size,
# #             "total_len": total_len
# #         }
# #         shares.append(share_packet)   
# #     for share in shares:
# #         print(f"Share {share['index']}: {share['share']}\n  Hash: {share['hash']}\n  Path: {share['path']}\n")
# #     shares.append(share_packet_t_plus_1)
# #     return shares
# import numpy as np
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
# import random

# # ---------------- AES helpers ----------------
# def generate_aes_key(length=16):
#     return bytes(random.randint(0, 255) for _ in range(length))

# def aes_encrypt_int(message: int, key: bytes):
#     msg_bytes = message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big')
#     cipher = AES.new(key, AES.MODE_CBC)
#     ct_bytes = cipher.encrypt(pad(msg_bytes, AES.block_size))
#     ct_int = int.from_bytes(ct_bytes, 'big')
#     return ct_int, cipher.iv

# def aes_decrypt_int(ct_int: int, key: bytes, iv: bytes):
#     ct_bytes = ct_int.to_bytes((ct_int.bit_length() + 7) // 8 or 1, 'big')
#     cipher = AES.new(key, AES.MODE_CBC, iv)
#     pt_bytes = unpad(cipher.decrypt(ct_bytes), AES.block_size)
#     return int.from_bytes(pt_bytes, 'big')

# # ---------------- ECC helpers ----------------
# def ecc_encrypt_key(key: bytes):
#     private_key = ec.generate_private_key(ec.SECP256R1())
#     public_key = private_key.public_key()
#     shared_key = private_key.exchange(ec.ECDH(), public_key)
#     derived_key = HKDF(
#         algorithm=hashes.SHA256(),
#         length=len(key),
#         salt=None,
#         info=b'handshake data'
#     ).derive(shared_key)
#     encrypted_key = bytes(k ^ d for k, d in zip(key, derived_key))
#     return encrypted_key, private_key, public_key

# def ecc_decrypt_key(enc_key: bytes, private_key, public_key):
#     shared_key = private_key.exchange(ec.ECDH(), public_key)
#     derived_key = HKDF(
#         algorithm=hashes.SHA256(),
#         length=len(enc_key),
#         salt=None,
#         info=b'handshake data'
#     ).derive(shared_key)
#     key = bytes(k ^ d for k, d in zip(enc_key, derived_key))
#     return key

# # ---------------- LSDT helpers ----------------
# def generate_B_matrix(t):
#     if t==2: B=np.array([[0,1],[1,1]],dtype=int)
#     elif t==3: B=np.array([[1,1,1],[1,1,0],[1,0,1]],dtype=int)
#     else:
#         gen=np.zeros(t,dtype=int)
#         gen[0]=1; gen[2]=1; gen[-1]=1
#         B=np.zeros((t,t),dtype=int)
#         for i in range(t): B[i]=np.roll(gen,i)
#     return B

# def intlist_to_bitmatrix(C):
#     max_bits=max(c.bit_length() for c in C)
#     bit_matrix=np.zeros((len(C),max_bits),dtype=int)
#     for i,c in enumerate(C):
#         bits=list(map(int,bin(c)[2:].zfill(max_bits)))
#         bit_matrix[i]=bits
#     return bit_matrix

# def bitmatrix_to_binlist(C_bits):
#     bin_list=[]
#     width=C_bits.shape[1]
#     for row in C_bits:
#         bin_str=''.join(str(b) for b in row)
#         bin_list.append('0b'+bin_str.zfill(width))
#     return bin_list

# def generate_shares_bitwise(C):
#     t=len(C)
#     C_bits=intlist_to_bitmatrix(C)
#     B=generate_B_matrix(t)
#     b_t1=np.bitwise_xor.reduce(B,axis=0)
#     B_ext=np.vstack([B,b_t1])
#     shares=[]
#     max_bits=C_bits.shape[1]
#     for i in range(t+1):
#         row=B_ext[i]
#         s_bits=np.zeros(max_bits,dtype=int)
#         for j in range(t):
#             if row[j]==1: s_bits ^= C_bits[j]
#         shares.append(s_bits)
#     return B_ext, shares

# def mod2_matrix_inverse(A):
#     n=A.shape[0]
#     A=A.copy()%2
#     I=np.eye(n,dtype=int)
#     for col in range(n):
#         pivot_row=-1
#         for row in range(col,n):
#             if A[row,col]==1: pivot_row=row; break
#         if pivot_row==-1: raise ValueError("Matrix not invertible")
#         if pivot_row!=col: A[[col,pivot_row]]=A[[pivot_row,col]]; I[[col,pivot_row]]=I[[pivot_row,col]]
#         for row in range(n):
#             if row!=col and A[row,col]==1: A[row]^=A[col]; I[row]^=I[col]
#     return I%2

# def reconstruct_C_bitwise(T_rows, chosen_shares_bits):
#     T=np.array(T_rows,dtype=int)%2
#     T_inv=mod2_matrix_inverse(T)
#     max_bits=chosen_shares_bits[0].shape[0]
#     C_rec=np.zeros((T_inv.shape[1],max_bits),dtype=int)
#     for bit_idx in range(max_bits):
#         s_vec=np.array([row[bit_idx] for row in chosen_shares_bits],dtype=int)
#         c_vec=np.zeros(T_inv.shape[1],dtype=int)
#         for i in range(T_inv.shape[1]):
#             val=0
#             for j in range(T_inv.shape[0]):
#                 val^=T_inv[i,j] & s_vec[j]
#             c_vec[i]=val
#         C_rec[:,bit_idx]=c_vec
#     return C_rec

# def split_message_to_parts(m:int,t:int):
#     bin_str=bin(m)[2:]
#     n=len(bin_str)
#     part_len=(n+t-1)//t
#     total_len=part_len*t
#     bin_str_padded=bin_str.zfill(total_len)
#     C=[]
#     for i in range(t):
#         part_bits=bin_str_padded[i*part_len:(i+1)*part_len]
#         C.append(int(part_bits,2))
#     return C

# # ---------------- Demo with all prints ----------------
# def message_generation_and_sharing(t):
#     m = int(input("Enter integer message to transmit: "))

#     print("\n--- Step 1: Generate AES key ---")
#     aes_key = generate_aes_key()
#     print("Original AES key:", aes_key.hex())

#     print("\n--- Step 2: AES Encrypt message ---")
#     ct_int, iv = aes_encrypt_int(m, aes_key)
#     print("AES Encrypted message as integer:", ct_int)

#     print("\n--- Step 3: ECC Encrypt AES key ---")
#     enc_key, ecc_priv, ecc_pub = ecc_encrypt_key(aes_key)
#     enc_key_int = int.from_bytes(enc_key, 'big')
#     print("Encrypted AES key (integer):", enc_key_int)

#     print("\n--- Step 4: Generate Shares ---")
#     # AES key shares
#     C_key = split_message_to_parts(enc_key_int, t)
#     B_key, shares_key = generate_shares_bitwise(C_key)
#     print("\nB matrix for AES key:\n", B_key)
#     for i, s in enumerate(shares_key):
#         print(f"AES key share s{i+1}:", s)

#     # Message shares
#     C_msg = split_message_to_parts(ct_int, t)
#     B_msg, shares_msg = generate_shares_bitwise(C_msg)
#     print("\nB matrix for Encrypted Message:\n", B_msg)
#     for i, s in enumerate(shares_msg):
#         print(f"Message share s{i+1}:", s)

#     print("\n--- Step 5: Form Transmitted Messages ---")
#     messages = []
#     for _ in range(t+1):
#         i = random.randint(0, t)
#         j = random.randint(0, t)
#         messages.append(((i+1, shares_key[i]), (j+1, shares_msg[j])))
#     for idx, msg in enumerate(messages):
#         print(f"Message {idx+1}: {msg}")
#     return messages,iv,ecc_priv, ecc_pub,B_key, shares_key

#     # ========================= SINK NODE RECONSTRUCTION =========================
#     # print("\n--- Step 6: Sink Node Reconstruction (using any t shares) ---")
#     # received_indices = sorted(random.sample(range(t+1), t))
#     # print("Sink received shares indices:", [i+1 for i in received_indices])

#     # # Reconstruct AES key
#     # T_rows_key = [B_key[i] for i in received_indices]
#     # chosen_shares_key = [shares_key[i] for i in received_indices]
#     # C_rec_bits_key = reconstruct_C_bitwise(T_rows_key, chosen_shares_key)
#     # C_rec_ints_key = [int(''.join(map(str, row)), 2) for row in C_rec_bits_key]
#     # key_bin_str = ''.join(bin(c)[2:].zfill(C_rec_bits_key.shape[1]) for c in C_rec_ints_key)
#     # aes_key_rec = int(key_bin_str, 2).to_bytes(len(enc_key), 'big')
#     # print("\nReconstructed AES key (before ECC decryption):", aes_key_rec.hex())

#     # aes_key_final = ecc_decrypt_key(aes_key_rec, ecc_priv, ecc_pub)
#     # print("AES key after ECC decryption:", aes_key_final.hex())

#     # # Reconstruct Encrypted Message
#     # T_rows_msg = [B_msg[i] for i in received_indices]
#     # chosen_shares_msg = [shares_msg[i] for i in received_indices]

# def reconstuct_and_decrypt(recvd_index):
#     T_rows_key = [B_key[i] for i in received_indices]
#     C_rec_bits_msg = reconstruct_C_bitwise(T_rows_msg, chosen_shares_msg)
#     C_rec_ints_msg = [int(''.join(map(str, row)), 2) for row in C_rec_bits_msg]
#     ct_rec_int = 0
#     for part, row in zip(C_rec_ints_msg, C_rec_bits_msg):
#         ct_rec_int = (ct_rec_int << row.shape[0]) | part

#     # Decrypt original message
#     m_rec = aes_decrypt_int(ct_rec_int, aes_key_final, iv)
#     print("\nRecovered Original Message:", m_rec)

import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import random

# ---------------- AES helpers ----------------
def generate_aes_key(length=16):
    return bytes(random.randint(0, 255) for _ in range(length))

def aes_encrypt_int(message: int, key: bytes):
    msg_bytes = message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big')
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg_bytes, AES.block_size))
    return int.from_bytes(ct_bytes, 'big'), cipher.iv

def aes_decrypt_int(ct_int: int, key: bytes, iv: bytes):
    ct_bytes = ct_int.to_bytes((ct_int.bit_length() + 7) // 8 or 1, 'big')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return int.from_bytes(pt_bytes, 'big')

# ---------------- ECC helpers ----------------
def ecc_encrypt_key(key: bytes):
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    shared = priv.exchange(ec.ECDH(), pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=len(key),
        salt=None,
        info=b'handshake data'
    ).derive(shared)
    enc_key = bytes(k ^ d for k, d in zip(key, derived))
    return enc_key, priv, pub

def ecc_decrypt_key(enc_key: bytes, priv, pub):
    shared = priv.exchange(ec.ECDH(), pub)
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=len(enc_key),
        salt=None,
        info=b'handshake data'
    ).derive(shared)
    return bytes(k ^ d for k, d in zip(enc_key, derived))

# ---------------- LSDT helpers ----------------
def generate_B_matrix(t):
    if t == 2:
        return np.array([[0, 1], [1, 1]], dtype=int)
    elif t == 3:
        return np.array([[1, 1, 1], [1, 1, 0], [1, 0, 1]], dtype=int)
    else:
        gen = np.zeros(t, dtype=int)
        gen[0] = gen[2] = gen[-1] = 1
        B = np.zeros((t, t), dtype=int)
        for i in range(t):
            B[i] = np.roll(gen, i)
        return B

def intlist_to_bitmatrix(C):
    max_bits = max(c.bit_length() for c in C)
    bit_matrix = np.zeros((len(C), max_bits), dtype=int)
    for i, c in enumerate(C):
        bits = list(map(int, bin(c)[2:].zfill(max_bits)))
        bit_matrix[i] = bits
    return bit_matrix

def mod2_matrix_inverse(A):
    n = A.shape[0]
    A = A.copy() % 2
    I = np.eye(n, dtype=int)
    for col in range(n):
        pivot = next((row for row in range(col, n) if A[row, col] == 1), None)
        if pivot is None:
            raise ValueError("Matrix not invertible")
        if pivot != col:
            A[[col, pivot]] = A[[pivot, col]]
            I[[col, pivot]] = I[[pivot, col]]
        for row in range(n):
            if row != col and A[row, col] == 1:
                A[row] ^= A[col]
                I[row] ^= I[col]
    return I % 2

def reconstruct_C_bitwise(T_rows, chosen_shares_bits):
    T = np.array(T_rows, dtype=int) % 2
    T_inv = mod2_matrix_inverse(T)
    max_bits = chosen_shares_bits[0].shape[0]
    C_rec = np.zeros((T_inv.shape[1], max_bits), dtype=int)

    for bit in range(max_bits):
        s_vec = np.array([row[bit] for row in chosen_shares_bits], dtype=int)
        C_rec[:, bit] = T_inv.dot(s_vec) % 2

    return C_rec

def split_message_to_parts(m: int, t: int):
    bin_str = bin(m)[2:]
    n = len(bin_str)
    part_len = (n + t - 1) // t
    bin_str = bin_str.zfill(part_len * t)
    return [int(bin_str[i * part_len:(i + 1) * part_len], 2) for i in range(t)]

def generate_shares_bitwise(C):
    t = len(C)
    C_bits = intlist_to_bitmatrix(C)
    B = generate_B_matrix(t)
    b_t1 = np.bitwise_xor.reduce(B, axis=0)
    B_ext = np.vstack([B, b_t1])
    shares = []

    for i in range(t + 1):
        row = B_ext[i]
        s = np.zeros(C_bits.shape[1], dtype=int)
        for j in range(t):
            if row[j] == 1:
                s ^= C_bits[j]
        shares.append(s)

    return B_ext, shares

def generate_and_share(message: int, t: int):

    aes_key = generate_aes_key()
    ct_int, iv = aes_encrypt_int(message, aes_key)

    enc_key, ecc_priv, ecc_pub = ecc_encrypt_key(aes_key)
    enc_key_int = int.from_bytes(enc_key, 'big')

    # Generate AES key shares
    C_key = split_message_to_parts(enc_key_int, t)
    B_key, shares_key = generate_shares_bitwise(C_key)

    # Generate message shares
    C_msg = split_message_to_parts(ct_int, t)
    B_msg, shares_msg = generate_shares_bitwise(C_msg)

    return {
        "shares_key": shares_key,
        "shares_msg": shares_msg,
        "B_key": B_key,
        "B_msg": B_msg,
        "enc_key_len": len(enc_key),
        "ecc_priv": ecc_priv,
        "ecc_pub": ecc_pub,
        "iv": iv
    }
def reconstruct_and_decrypt(
        recv_indices,
        recv_key_shares,
        recv_msg_shares,
        B_key,
        B_msg,
        enc_key_len,
        ecc_priv,
        ecc_pub,
        iv):

    # ---- AES KEY reconstruction ----
    T_key = [B_key[i] for i in recv_indices]
    C_key_bits = reconstruct_C_bitwise(T_key, recv_key_shares)
    key_int = int(''.join(''.join(str(b) for b in row) for row in C_key_bits), 2)
    enc_key = key_int.to_bytes(enc_key_len, 'big')

    aes_key = ecc_decrypt_key(enc_key, ecc_priv, ecc_pub)

    # ---- MESSAGE reconstruction ----
    T_msg = [B_msg[i] for i in recv_indices]
    C_msg_bits = reconstruct_C_bitwise(T_msg, recv_msg_shares)
    msg_int = int(''.join(''.join(str(b) for b in row) for row in C_msg_bits), 2)

    recovered = aes_decrypt_int(msg_int, aes_key, iv)
    return recovered

# ========== PART 1 ==========
# data = generate_and_share(message=12345, t=3)

# # Example: sink receives any 3 shares
# indices = [0, 2, 3]

# recv_key = [data["shares_key"][i] for i in indices]
# recv_msg = [data["shares_msg"][i] for i in indices]

# # ========== PART 2 ==========
# original = reconstruct_and_decrypt(
#     indices,
#     recv_key,
#     recv_msg,
#     data["B_key"],
#     data["B_msg"],
#     data["enc_key_len"],
#     data["ecc_priv"],
#     data["ecc_pub"],
#     data["iv"]
# )

# print("Recovered:", original)