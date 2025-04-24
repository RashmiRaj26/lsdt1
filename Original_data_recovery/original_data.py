import numpy as np
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Message_encryption.encryption import decrypt_data  # Assuming this handles the final data decryption
from Message_encryption.invertible_matrix import generate_invertible_cyclic_matrix  # Assuming this generates the invertible cyclic matrix

def gf2_matrix_inverse(matrix):
    """Inverts a binary matrix (mod 2) using Gauss-Jordan elimination."""
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


# def rsa_decrypt(private_key, ciphertext):
    """Decrypt the ciphertext using RSA private key."""
    # return private_key.decrypt(
    #     ciphertext,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #     )
    # )


# def aes_decrypt(session_key, ciphertext):
    """Decrypt the ciphertext using AES with the session key."""
    # iv = ciphertext[:16]  # Assuming the first 16 bytes are the IV
    # ciphertext_data = ciphertext[16:]  # The rest is the actual ciphertext

    # cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
    # decryptor = cipher.decryptor()
    # plaintext = decryptor.update(ciphertext_data) + decryptor.finalize()
    # return plaintext


def recover_original_data(shares, sink_node, source_node_id, routing_table, private_key):
    # Step 1: Determine t (number of shares needed for recovery)
    max_nodes = len(routing_table[source_node_id])
    t = max_nodes - 1

    # Step 2: Generate cyclic invertible matrix B (over GF(2))
    B = generate_invertible_cyclic_matrix(t)
    B_T = B.T

    # Step 3: Collect t shares and form the share matrix S
    shares_sorted = sorted(shares[:t], key=lambda x: x["index"])
    S = np.array([list(x["share"]) for x in shares_sorted], dtype=np.uint8)

    # Step 4: Invert B transpose over GF(2)
    B_T_inv = gf2_matrix_inverse(B_T)

    # Step 5: Recover C = B_T_inv × S mod 2 (matrix multiplication in GF(2))
    C_matrix = (B_T_inv @ S) % 2

    # Step 6: Flatten C_matrix rows to reconstruct the full ciphertext
    full_cipher_bytes = bytes(C_matrix.flatten())

    print("\n📦 Reconstructed Full Ciphertext (Base64):")
    print(base64.b64encode(full_cipher_bytes).decode())

    # Step 7: Extract the session key and original data from the ciphertext
    # Assuming that the last part of the ciphertext contains AE.Enc(keyw, pk) (session key encrypted with RSA)
    # and the first part is the encrypted data (using AES with session key).
    
    # Step 7.1: Extract session key encrypted with RSA (last 256 bits of the ciphertext)
    session_key_encrypted = full_cipher_bytes[-256:]  # Adjust size if needed
    
    # Step 7.2: Decrypt the session key using the RSA private key
    session_key = rsa_decrypt(private_key, session_key_encrypted)

    print("✅ Decrypted session key:", session_key.hex())

    # Step 7.3: Decrypt the original data using AES with the session key
    original_data_encrypted = full_cipher_bytes[:-256]  # Assuming the rest is encrypted data
    original_data = aes_decrypt(session_key, original_data_encrypted)

    print("✅ Decrypted original data:", original_data.decode())
    return original_data

# Example usage
# if __name__ == '__main__':
#     # Simulate loading RSA private key (replace with actual private key loading)
#     from cryptography.hazmat.primitives import serialization

#     with open("path_to_private_key.pem", "rb") as key_file:
#         private_key = serialization.load_pem_private_key(
#             key_file.read(),
#             password=None,
#             backend=default_backend()
#         )

#     # Example shares (Simulated shares with "index" and "share" as binary vectors)
#     shares = [
#         {"index": 1, "share": np.array([1, 0, 1], dtype=np.uint8)},
#         {"index": 2, "share": np.array([0, 1, 1], dtype=np.uint8)},
#         {"index": 3, "share": np.array([1, 1, 0], dtype=np.uint8)}
#     ]

#     # Simulated routing table (replace with actual routing data)
#     routing_table = {1: [1, 2, 3]}

#     # Simulated sink node (this would be replaced with actual node details)
#     sink_node = {}

#     # Recover the original data
#     recovered_data = recover_original_data(shares, sink_node, source_node_id=1, routing_table=routing_table, private_key=private_key)
#     print("✅ Final recovered data:", recovered_data.decode())
