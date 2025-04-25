import numpy as np
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Message_encryption.encryption import decrypt_data  
from Message_encryption.invertible_matrix import generate_invertible_cyclic_matrix  

def gf2_matrix_inverse(matrix):
    n = matrix.shape[0]
    A = matrix.copy() % 2
    I = np.identity(n, dtype=np.uint8)

    for i in range(n):
        if A[i, i] == 0:
            for j in range(i + 1, n):
                if A[j, i] == 1:
                    A[[i, j]] = A[[j, i]]
                    I[[i, j]] = I[[j, i]]
                    break
            else:
                raise ValueError("Matrix is not invertible in GF(2)")

        for j in range(n):
            if j != i and A[j, i] == 1:
                A[j] ^= A[i]
                I[j] ^= I[i]

    return I % 2

def recover_original_data(shares, sink_node, source_node_id, routing_table, private_key):
    max_nodes = len(routing_table[source_node_id])
    t = max_nodes - 1

    B = generate_invertible_cyclic_matrix(t)
    B_T = B.T
    temp = ""
    if len(shares) > (t+1):
        temp = shares[-1]
        shares.pop()
    shares_sorted = sorted(shares[:t], key=lambda x: x["index"])
    S = np.array([list(x["share"]) for x in shares_sorted], dtype=np.uint8)

    B_T_inv = gf2_matrix_inverse(B_T)

    C_matrix = (B_T_inv @ S) % 2

    full_cipher_bytes = temp

    print("\n📦 Reconstructed Full Ciphertext (Base64):")
    print(full_cipher_bytes)
    print(" ")
    original_data=decrypt_data(sink_node,full_cipher_bytes)
    return original_data