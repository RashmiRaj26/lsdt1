from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import secrets

class SensorNode:
    def __init__(self, node_id, location, initial_energy, communication_radius):
        self.node_id = node_id
        self.location = location
        self.initial_energy = initial_energy
        self.communication_radius = communication_radius
        self.routing_paths = []

    def __repr__(self):
        return (f"SensorNode(id={self.node_id}, location={self.location}, "
                f"initial_energy={self.initial_energy}, "
                f"communication_radius={self.communication_radius})")

    def encrypt_data(self, data, sink_node):
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

    def decrypt_data(self, encrypted_data, sink_node):
        encrypted_payload = base64.b64decode(encrypted_data["SE.Enc(dat, keyw)"])
        encrypted_key = base64.b64decode(encrypted_data["AE.Enc(keyw, pk)"])

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
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext.decode('utf-8')


class SinkNode:
    def __init__(self, location):
        self.location = location
        self.public_key = None
        self.private_key = None
        self.weighting_coefficient = 0.5
        self.hash_function = None
        self.max_hops = 5

    def __repr__(self):
        return (f"SinkNode(location={self.location}, "
                f"weighting_coefficient={self.weighting_coefficient}, "
                f"max_hops={self.max_hops})")

    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.private_key = private_key
        self.public_key = private_key.public_key()


if __name__ == "__main__":
    sink_node = SinkNode(location="Sink Location")
    sink_node.generate_keys()

    sensor_node = SensorNode(node_id=1, location="Sensor Location", initial_energy=100, communication_radius=50)
    data = "This is some plaintext data that needs to be encrypted."

    encrypted_data = sensor_node.encrypt_data(data, sink_node)
    print("Encrypted Data:", encrypted_data)

    decrypted_data = sensor_node.decrypt_data(encrypted_data, sink_node)
    print("Decrypted Data:", decrypted_data)
