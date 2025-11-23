import numpy as np
import math
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA256

# ============================================================
# Helper printing
# ============================================================
def print_hex(label, data):
    print(f"{label} ({len(data)} bytes): {data.hex()}")

# ============================================================
# 1. Generate invertible cyclic matrix B
# ============================================================
def generate_cyclic_matrix(t):
    if t == 2:
        return np.array([[0, 1],
                         [1, 0]], dtype=int)
    elif t == 3:
        return np.array([[1, 1, 1],
                         [1, 1, 0],
                         [1, 0, 1]], dtype=int)
    else:
        # generator = (1,0,1,0,...,0,1)
        gen = [1, 0, 1] + [0]*(t-4) + [1]
        B = np.zeros((t, t), dtype=int)
        B[0] = gen
        for i in range(1, t):
            B[i] = np.roll(B[i-1], 1)
        return B

# ============================================================
# 2. Split message into t blocks
# ============================================================
def split_message(msg_bits, t):
    L = len(msg_bits)
    block_len = math.ceil(L / t)
    blocks = []

    for i in range(t):
        start = i * block_len
        end = start + block_len
        blk = msg_bits[start:end]
        if len(blk) < block_len:
            blk += [0] * (block_len - len(blk))
        blocks.append(np.array(blk, dtype=int))

    return blocks, block_len

# ============================================================
# 3. Generate shares using B_extended
# ============================================================
def generate_shares(blocks, B):
    t = B.shape[0]
    # Extended matrix: add XOR of all rows as (t+1)-th row
    B_extended = np.vstack((B, np.bitwise_xor.reduce(B, axis=0)))

    print("\n===== EXTENDED MATRIX B ( (t+1) x t ) =====")
    print(B_extended)

    shares = []
    for row in B_extended:
        s = np.zeros_like(blocks[0])
        for i in range(t):
            if row[i] == 1:
                s ^= blocks[i]
        shares.append(s)

    return shares, B_extended

# ============================================================
# 4. GF(2) inverse
# ============================================================
def gf2_inverse(A):
    n = A.shape[0]
    A = A.copy() % 2
    I = np.eye(n, dtype=int)

    for col in range(n):
        pivot = None
        for row in range(col, n):
            if A[row, col] == 1:
                pivot = row
                break
        if pivot is None:
            raise ValueError("Matrix is singular over GF(2).")

        if pivot != col:
            A[[col, pivot]] = A[[pivot, col]]
            I[[col, pivot]] = I[[pivot, col]]

        for row in range(n):
            if row != col and A[row, col] == 1:
                A[row] = (A[row] + A[col]) % 2
                I[row] = (I[row] + I[col]) % 2

    return I

# ============================================================
# 5. Reconstruction
# ============================================================
def reconstruct_blocks(selected_shares, selected_indices, B_extended, t):
    block_len = len(selected_shares[0])

    # Build B_sub using selected rows from B_extended
    B_sub = B_extended[selected_indices, :t]
    print("\n===== B_sub (used for reconstruction) =====")
    print(B_sub)

    B_inv = gf2_inverse(B_sub)
    print("\n===== Inverse(B_sub) over GF(2) =====")
    print(B_inv)

    S_sub = np.array(selected_shares, dtype=int)  # shape: (t, block_len)

    # blocks_matrix = B_inv * S_sub (mod 2)
    blocks_matrix = (B_inv @ S_sub) % 2          # shape: (t, block_len)

    reconstructed = [blocks_matrix[i].copy() for i in range(t)]
    return reconstructed

# ============================================================
# Bit/Byte conversion helpers
# ============================================================
def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b <<= 1
            if i + j < len(bits):
                b |= bits[i + j]
        out.append(b)
    return bytes(out)

def bytes_to_bits(bts):
    bits = []
    for b in bts:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits

# ============================================================
# ECC REAL ENCRYPTION (ECIES-like using ECDH + AES-GCM)
# ============================================================
def ecc_encrypt(public_key, plaintext_bytes):
    # Ephemeral private/public key
    eph = ECC.generate(curve="P-256")

    # Shared secret: public_key.pointQ * eph_private_scalar
    shared = public_key.pointQ * eph.d
    shared_bytes = int(shared.x).to_bytes(32, 'big')

    # Derive AES-GCM key from shared secret
    aes_key = SHA256.new(shared_bytes).digest()

    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)

    return eph.public_key().export_key(format="DER"), ciphertext, tag, cipher.nonce

def ecc_decrypt(private_key, eph_pub_der, ciphertext, tag, nonce):
    eph_pub = ECC.import_key(eph_pub_der)

    # Shared secret: eph_pub.pointQ * private_scalar
    shared = eph_pub.pointQ * private_key.d
    shared_bytes = int(shared.x).to_bytes(32, 'big')

    aes_key = SHA256.new(shared_bytes).digest()

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    msg_bits = list(map(int, input("Enter message bits (0/1 separated): ").split()))
    print("\n===== ORIGINAL MESSAGE BITS =====")
    print(msg_bits)

    # --------------------------------------------------------------------
    # AES encrypt the message
    # --------------------------------------------------------------------
    msg_bytes = bits_to_bytes(msg_bits)
    aes_key = get_random_bytes(16)  # 128-bit session key
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)
    ct_data = aes_cipher.encrypt(pad(msg_bytes, AES.block_size))

    print_hex("\nAES session key", aes_key)
    print_hex("AES IV", aes_cipher.iv)
    print_hex("AES encrypted message", ct_data)

    # --------------------------------------------------------------------
    # ECC encrypt the AES key (ECIES-like)
    # --------------------------------------------------------------------
    sink_priv = ECC.generate(curve="P-256")
    sink_pub = sink_priv.public_key()

    eph_pub_der, ct_key, tag_key, nonce_key = ecc_encrypt(sink_pub, aes_key)

    print_hex("\nEphemeral ECC public key (DER)", eph_pub_der)
    print_hex("Nonce for AES-GCM (key wrap)", nonce_key)
    print_hex("Tag for AES-GCM (key wrap)", tag_key)
    print_hex("Encrypted AES key", ct_key)

    # --------------------------------------------------------------------
    # Combine all fields into one byte string for sharing
    # --------------------------------------------------------------------
    combined = eph_pub_der + nonce_key + tag_key + ct_key + aes_cipher.iv + ct_data
    combined_bits = bytes_to_bits(combined)

    print("\n===== COMBINED PAYLOAD (before sharing) =====")
    print_hex("Combined bytes", combined)
    print("Combined bits length:", len(combined_bits))
    print("Combined bits (first 64):", combined_bits[:64], "..." if len(combined_bits) > 64 else "")

    # --------------------------------------------------------------------
    # Generate shares using cyclic matrix
    # --------------------------------------------------------------------
    t = int(input("\nEnter t (number of blocks / threshold): "))
    blocks, block_len = split_message(combined_bits, t)

    print("\n===== BLOCKS (after splitting combined bits) =====")
    for i, b in enumerate(blocks):
        print(f"Block {i}: {b}")

    B = generate_cyclic_matrix(t)
    print("\n===== CYCLIC MATRIX B =====")
    print(B)

    shares, B_extended = generate_shares(blocks, B)

    print("\n===== GENERATED SHARES =====")
    for i, s in enumerate(shares):
        print(f"Share {i}: {s}")

    # --------------------------------------------------------------------
    # Reconstruction from any t shares
    # --------------------------------------------------------------------
    selected_indices = list(map(int, input(f"\nEnter {t} share indices to reconstruct (0 to {len(shares)-1}): ").split()))
    if len(selected_indices) != t:
        raise ValueError("You must select exactly t shares.")

    selected_shares = [shares[i] for i in selected_indices]

    rec_blocks = reconstruct_blocks(selected_shares, selected_indices, B_extended, t)
    rec_bits = np.concatenate(rec_blocks)[:len(combined_bits)]
    rec_bytes = bits_to_bytes(rec_bits)

    print_hex("\n===== RECONSTRUCTED COMBINED BYTES =====", rec_bytes)

    # --------------------------------------------------------------------
    # Split reconstructed combined bytes back into fields
    # --------------------------------------------------------------------
    off = 0
    len_eph = len(eph_pub_der)
    len_nonce = len(nonce_key)
    len_tag = len(tag_key)
    len_ct_key = len(ct_key)
    len_iv = len(aes_cipher.iv)
    len_ct_data = len(ct_data)

    rec_eph_pub = rec_bytes[off:off+len_eph];      off += len_eph
    rec_nonce   = rec_bytes[off:off+len_nonce];    off += len_nonce
    rec_tag     = rec_bytes[off:off+len_tag];      off += len_tag
    rec_ct_key  = rec_bytes[off:off+len_ct_key];   off += len_ct_key
    rec_iv      = rec_bytes[off:off+len_iv];       off += len_iv
    rec_ct      = rec_bytes[off:off+len_ct_data];  off += len_ct_data

    print("\n===== RECONSTRUCTED FIELDS =====")
    print_hex("Recovered ephemeral pubkey", rec_eph_pub)
    print_hex("Recovered nonce", rec_nonce)
    print_hex("Recovered tag", rec_tag)
    print_hex("Recovered encrypted AES key", rec_ct_key)
    print_hex("Recovered AES IV", rec_iv)
    print_hex("Recovered AES ciphertext", rec_ct)

    # --------------------------------------------------------------------
    # ECC decrypt AES key
    # --------------------------------------------------------------------
    rec_key = ecc_decrypt(sink_priv, rec_eph_pub, rec_ct_key, rec_tag, rec_nonce)
    print_hex("\n===== DECRYPTED AES KEY (after reconstruction) =====", rec_key)

    # --------------------------------------------------------------------
    # AES decrypt final message
    # --------------------------------------------------------------------
    aes_dec = AES.new(rec_key, AES.MODE_CBC, iv=rec_iv)
    msg_final = unpad(aes_dec.decrypt(rec_ct), AES.block_size)
    msg_final_bits = bytes_to_bits(msg_final)

    print("\n===== FINAL RECONSTRUCTED MESSAGE BITS =====")
    print(msg_final_bits[:len(msg_bits)])

    print("\nMATCH:", msg_bits == msg_final_bits[:len(msg_bits)])
