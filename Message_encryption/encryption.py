import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

def encrypt_data(value, sink_node):
    # Determine type and serialize accordingly
    if isinstance(value, float):
        type_flag = b'\x01'
        binary_data = struct.pack("d", value)
    elif isinstance(value, str):
        type_flag = b'\x02'
        binary_data = value.encode('utf-8')
    else:
        raise TypeError("Unsupported data type. Only float and string are allowed.")

    binary_data = type_flag + binary_data  # Prefix with type indicator
    keyw = secrets.token_bytes(32)  # AES-256 key
    iv = secrets.token_bytes(12)    # 12-byte IV for GCM

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
    return base64.b64encode(combined).decode('utf-8')

def decrypt_data(sink_node, encoded_combined_data):
    combined = base64.b64decode(encoded_combined_data)
    key_len = struct.unpack("I", combined[:4])[0]
    encrypted_key = combined[4:4+key_len]
    encrypted_payload = combined[4+key_len:]

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

    # First byte is the type flag
    type_flag = binary_data[0:1]
    actual_data = binary_data[1:]

    if type_flag == b'\x01':  # float
        return struct.unpack("d", actual_data)[0]
    elif type_flag == b'\x02':  # string
        return actual_data.decode('utf-8')
    else:
        raise ValueError("Unknown data type flag in decrypted data.")
