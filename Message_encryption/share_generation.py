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
    """
    Encrypt an integer message using AES-CBC.
    Returns: ct_int, iv, ct_len (ct_len = len(ct_bytes) so we can reconstruct exact bytes later)
    """
    msg_bytes = message.to_bytes((message.bit_length() + 7) // 8 or 1, 'big')
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(msg_bytes, AES.block_size))
    return int.from_bytes(ct_bytes, 'big'), cipher.iv, len(ct_bytes)

def aes_decrypt_int(ct_int: int, key: bytes, iv: bytes, ct_len: int):
    """
    Decrypt integer ciphertext using AES-CBC. ct_len is required to preserve leading zero bytes.
    """
    ct_bytes = ct_int.to_bytes(ct_len, 'big')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_bytes = unpad(cipher.decrypt(ct_bytes), AES.block_size)
    return int.from_bytes(pt_bytes, 'big')

# ---------------- ECC helpers ----------------
def ecc_encrypt_key(key: bytes):
    """
    Simple wrapper that creates an ECC private/public key pair and uses ECDH with its own public key.
    NOTE: this mirrors the original approach in your code (priv + pub returned together).
    It derives a keystream of length len(key) and XORs with the key to create enc_key.
    """
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()
    # derive shared (priv with pub)
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
    """
    Reverse the XOR using the same ECDH-derived keystream.
    """
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
    """
    Convert a list of integers C (each representing a part) into a bit-matrix
    shape = (len(C), max_bits). Each row is the binary representation of that part,
    left-to-right most-significant-bit first.
    """
    max_bits = max((c.bit_length() for c in C), default=1)
    bit_matrix = np.zeros((len(C), max_bits), dtype=int)
    for i, c in enumerate(C):
        bits = list(map(int, bin(c)[2:].zfill(max_bits)))
        bit_matrix[i] = bits
    return bit_matrix

def mod2_matrix_inverse(A):
    """
    Invert matrix A over GF(2). A must be square and invertible mod 2.
    """
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
    """
    Reconstruct the original C bit-matrix given:
      - T_rows: list/array of rows taken from B_ext (forming square transform T)
      - chosen_shares_bits: list of share bit-arrays (each array is shape (num_bits,))
    Returns C_rec: numpy array shape (t, max_bits) where t = original number of parts
    (This is the same shape produced by intlist_to_bitmatrix(C)).
    """
    T = np.array(T_rows, dtype=int) % 2
    T_inv = mod2_matrix_inverse(T)
    max_bits = chosen_shares_bits[0].shape[0]
    # T_inv.shape[1] == t (number of original parts)
    C_rec = np.zeros((T_inv.shape[1], max_bits), dtype=int)

    for bit in range(max_bits):
        s_vec = np.array([row[bit] for row in chosen_shares_bits], dtype=int)
        C_rec[:, bit] = T_inv.dot(s_vec) % 2

    return C_rec

def split_message_to_parts(m: int, t: int):
    """
    Split integer m into t equal-length bit-parts (returned as integers).
    """
    bin_str = bin(m)[2:]
    n = len(bin_str)
    part_len = (n + t - 1) // t
    bin_str = bin_str.zfill(part_len * t)
    return [int(bin_str[i * part_len:(i + 1) * part_len], 2) for i in range(t)]

def generate_shares_bitwise(C):
    """
    Given list C of t integer parts, create bitwise shares using B_ext (t+1 rows).
    Returns B_ext and shares (list length t+1) where each share is a 1D bit-array.
    """
    t = len(C)
    C_bits = intlist_to_bitmatrix(C)  # shape (t, max_bits)
    B = generate_B_matrix(t)          # shape (t, t)
    b_t1 = np.bitwise_xor.reduce(B, axis=0)  # 1D array length t
    B_ext = np.vstack([B, b_t1])      # shape (t+1, t)
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
    """
    Top-level function:
      - generate AES key
      - encrypt message -> ct_int, iv, ct_len
      - ecc-encrypt AES key -> enc_key (bytes), priv, pub
      - split enc_key_int into t parts -> shares_key (t+1 shares)
      - split ct_int into t parts -> shares_msg (t+1 shares)
    Returns dictionary containing everything a receiver needs (except the original secret).
    """
    aes_key = generate_aes_key()
    ct_int, iv, ct_len = aes_encrypt_int(message, aes_key)

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
        "enc_key_len": len(enc_key),  # byte-length of enc_key
        "ct_len": ct_len,            # ciphertext byte length (important!)
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
        ct_len,
        ecc_priv,
        ecc_pub,
        iv):
    """
    Reconstruct AES key and ciphertext from selected shares and decrypt.
    recv_indices: list of indices chosen from the B_ext (length must equal t to form square T)
    recv_key_shares: list of share-bit-arrays corresponding to recv_indices (len == len(recv_indices))
    recv_msg_shares: list of share-bit-arrays corresponding to recv_indices (len == len(recv_indices))
    """

    # ---- AES KEY reconstruction ----
    T_key = [B_key[i] for i in recv_indices]               # shape (t, t)
    C_key_bits = reconstruct_C_bitwise(T_key, recv_key_shares)  # shape (t, bits)

    # Each row in C_key_bits corresponds to one original part (MSB->LSB).
    # Rebuild the original bitstring by concatenating rows in order.
    key_bitstring = ''.join(''.join(str(bit) for bit in row) for row in C_key_bits)
    if key_bitstring == '':
        key_int = 0
    else:
        key_int = int(key_bitstring, 2)
    enc_key = key_int.to_bytes(enc_key_len, 'big')

    aes_key = ecc_decrypt_key(enc_key, ecc_priv, ecc_pub)

    # ---- MESSAGE reconstruction ----
    T_msg = [B_msg[i] for i in recv_indices]
    C_msg_bits = reconstruct_C_bitwise(T_msg, recv_msg_shares)

    # Reconstruct message bitstring by concatenating rows (parts) in original order.
    msg_bitstring = ''.join(''.join(str(bit) for bit in row) for row in C_msg_bits)
    if msg_bitstring == '':
        msg_int = 0
    else:
        msg_int = int(msg_bitstring, 2)

    recovered = aes_decrypt_int(msg_int, aes_key, iv, ct_len)
    return recovered

# ========== PART 1 ========== (example usage)
if __name__ == "__main__":
    # create shares from message
    data = generate_and_share(message=12345, t=3)

    # Example: sink receives any 3 shares (for t=3, pick any 3 of the 4 available shares)
    indices = [0, 2, 3]

    recv_key = [data["shares_key"][i] for i in indices]
    recv_msg = [data["shares_msg"][i] for i in indices]

    # ========== PART 2 ==========
    original = reconstruct_and_decrypt(
        indices,
        recv_key,
        recv_msg,
        data["B_key"],
        data["B_msg"],
        data["enc_key_len"],
        data["ct_len"],
        data["ecc_priv"],
        data["ecc_pub"],
        data["iv"]
    )

    print("Recovered:", original)
