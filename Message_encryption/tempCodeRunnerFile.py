import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

def encrypt_data(value, sink_node):
    # Convert float to 8-byte binary (double precision)
    binary_data = struct.pack("d", value)

    keyw = secrets.token_bytes(32)  # AES-256 key
    iv = secrets.token_bytes(12)    # GCM IV

    cipher = Cipher(algorithms.AES(keyw), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(binary_data) + encryptor.finalize()
    tag = encryptor.tag
    encrypted_payload = iv + ciphertext + tag

    encrypted_key = sink_node.public_key.encrypt(
        keyw,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    key_len_prefix = struct.pack("I", len(encrypted_key))
    combined = key_len_prefix + encrypted_key + encrypted_payload
    print("✔️ Original combined data (base64):", base64.b64encode(combined).decode())
    return base64.b64encode(combined).decode('utf-8')

def decrypt_data(sink_node, encoded_combined_data):
    combined = base64.b64decode(encoded_combined_data)
    key_len = struct.unpack("I", combined[:4])[0]
    encrypted_key = combined[4:4+key_len]
    encrypted_payload = combined[4+key_len:]
    # key_len = struct.unpack("I", combined[:4])[0]
    print("🔑 Declared key_len:", key_len)
    print("🧩 Actual combined length:", len(combined))
    print("📦 Expected encrypted_key length:", len(combined[4:4+key_len]))
    print("🔍 RSA key size (bytes):", sink_node.private_key.key_size // 8)

    keyw = sink_node.private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = encrypted_payload[:12]
    tag = encrypted_payload[-16:]
    ciphertext = encrypted_payload[12:-16]

    cipher = Cipher(algorithms.AES(keyw), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    binary_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Convert binary back to float
    return struct.unpack("d", binary_data)[0]
