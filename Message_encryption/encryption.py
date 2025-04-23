from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
def encrypt_data(data, sink_node):
    keyw = secrets.token_bytes(32)
    iv = secrets.token_bytes(12)

    cipher = Cipher(algorithms.AES(keyw), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
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

    return {
        "SE.Enc(dat, keyw)": base64.b64encode(encrypted_payload).decode('utf-8'),
        "AE.Enc(keyw, pk)": base64.b64encode(encrypted_key).decode('utf-8')
    }

def decrypt_data(sink, encrypted_data):
    encrypted_payload = base64.b64decode(encrypted_data["SE.Enc(dat, keyw)"])
    encrypted_key = base64.b64decode(encrypted_data["AE.Enc(keyw, pk)"])

    keyw = sink.private_key.decrypt(
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
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode('utf-8')
