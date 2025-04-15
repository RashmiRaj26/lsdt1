import math
import random
from hashlib import sha256

# Simulated symmetric encryption/decryption for simplicity
def encrypt(data, key):
    return f"enc({data})"

def decrypt(data, key):
    if data.startswith("enc(") and data.endswith(")"):
        return data[4:-1]
    return data

# Energy transmission model
def energy_transmit(duv, L, D0=50, Eelec=0.1, fs=0.01, mp=0.001):
    if duv <= D0:
        return L * Eelec + L * fs * (duv ** 2)
    else:
        return L * Eelec + L * mp * (duv ** 4)

# Message class
class Message:
    def __init__(self, msg_id, share, timestamp, path=[], path_star=[]):
        self.id = msg_id
        self.si = share
        self.hash = sha256(f"{msg_id}{share}".encode()).hexdigest()
        self.path = path
        self.path_star = path_star
        self.timestamp = timestamp

# Node message transmission logic
def transmit_message(source_node, message, sink_node, lambda_weight=2, message_bit_length=512):
    visited_nodes = set(message.path_star)
    candidates = [
        n for n in source_node.neighbors
        if n.node_id not in visited_nodes and not n.detected_as_malicious
    ]

    if not candidates:
        print(f"[!] Node {source_node.node_id} has no eligible neighbors to forward.")
        return

    best_node = None
    max_IF = -1

    for neighbor in candidates:
        duv = source_node.distance_to(neighbor)
        dvjs = neighbor.distance_to(sink_node)
        ET = energy_transmit(duv, message_bit_length)

        pvj = neighbor.reputation
        pa = lambda_weight if neighbor.node_id in message.path else 1

        IF = (pvj * pa * neighbor.energy) / (ET * (dvjs ** 2))
        if IF > max_IF:
            max_IF = IF
            best_node = neighbor

    if best_node:
        # Deduct energy for transmission
        duv = source_node.distance_to(best_node)
        energy_used = energy_transmit(duv, message_bit_length)
        source_node.energy -= energy_used

        message.path_star.append(best_node.node_id)
        best_node.receive_message(message, source_node)

        # Recurse until message reaches sink
        if best_node == sink_node:
            print(f"[✓] Message {message.id} delivered to sink by Node {best_node.node_id}")
        else:
            transmit_message(best_node, message, sink_node, lambda_weight, message_bit_length)
    else:
        print(f"[X] Node {source_node.node_id} failed to forward message.")

# Overriding receive_message to accept forwarding
def receive_message_override(self, message, sender):
    print(f"Node {self.node_id} received message {message.id} from Node {sender.node_id}")
    self.messages_forwarded[message.id] = message

# Assume SensorNode is defined elsewhere
# You must attach this method to SensorNode like:
# SensorNode.receive_message = receive_message_override
