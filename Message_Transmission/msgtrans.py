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
    return L * Eelec + L * (fs * duv ** 2 if duv <= D0 else mp * duv ** 4)

# Message class
class Message:
    def __init__(self, msg_id, share, timestamp, path=[], path_star=[]):
        self.id = msg_id
        self.si = share
        self.hash = sha256(f"{msg_id}{share}".encode()).hexdigest()
        self.path = path
        self.path_star = path_star
        self.timestamp = timestamp

# Random exponentiation placeholder for g^alpha, g^beta
def generate_random_exponent():
    return random.randint(1, 1000)

def simulate_group_exp(base, exponent):
    return f"g^{exponent}"

# Message transmission function (5-step based)
def transmit_message(source_node, message, sink_node, lambda_weight=2, message_bit_length=512):
    print(f"\n[Node {source_node.node_id}] Initiating Message Transmission")

    visited_nodes = set(message.path_star)
    Neiu = [n for n in source_node.neighbors if n.node_id not in visited_nodes and not n.detected_as_malicious]

    if not Neiu:
        print(f"[!] Node {source_node.node_id} has no eligible neighbors to forward.")
        return

    # Step 1: Send query Qj = {IDu, g^alpha_j, TS} to eligible neighbors
    alpha_j = generate_random_exponent()
    g_alpha_j = simulate_group_exp('g', alpha_j)

    responses = {}

    for vj in Neiu:
        print(f"[Query] Node {source_node.node_id} -> Node {vj.node_id} | Qj = {{IDu: {source_node.node_id}, g^alpha_j: {g_alpha_j}, TS: {message.timestamp}}}")
        beta_j = generate_random_exponent()
        g_beta_j = simulate_group_exp('g', beta_j)
        g_alpha_beta_j = simulate_group_exp(g_alpha_j, beta_j)
        dvjs = vj.distance_to(sink_node)

        ciphertext = encrypt(f"{vj.node_id}|{vj.energy}|{dvjs}|{message.timestamp}|{g_alpha_beta_j}", g_alpha_beta_j)
        responses[vj] = (ciphertext, g_beta_j)

    # Step 2-3: Decrypt each response and extract values
    best_node = None
    max_IF = -1

    for vj, (ciphertext, g_beta_j) in responses.items():
        g_alpha_beta_j = simulate_group_exp(g_beta_j, alpha_j)
        decrypted = decrypt(ciphertext, g_alpha_beta_j)
        try:
            IDvj, E_vj, dvjs, TS, proof = decrypted.split('|')
            IDvj, E_vj, dvjs = int(IDvj), float(E_vj), float(dvjs)
        except:
            continue

        duvj = source_node.distance_to(vj)
        ET = energy_transmit(duvj, message_bit_length)

        # Step 4: Compute IF value for each neighbor
        pvj = vj.reputation  # Default = 1 initially
        pa = lambda_weight if vj.node_id in message.path else 1
        IF = (pvj * pa * E_vj) / (ET * ((dvjs ** 2) + 1e-6))

        print(f"[IF Computation] IF({source_node.node_id},{vj.node_id}) = ({pvj} * {pa} * {E_vj}) / ({ET} * {dvjs}^2) = {IF:.4f}")

        if IF > max_IF:
            max_IF = IF
            best_node = vj

    # Step 5: Forward message to next-hop node with largest IF
    if best_node:
        duv = source_node.distance_to(best_node)
        energy_used = energy_transmit(duv, message_bit_length)
        source_node.energy -= energy_used
        message.path_star.append(best_node.node_id)
        best_node.receive_message(message, source_node)

        if best_node == sink_node:
            print(f"[✓] Message {message.id} delivered to sink by Node {best_node.node_id}")
        else:
            transmit_message(best_node, message, sink_node, lambda_weight, message_bit_length)
    else:
        print(f"[X] Node {source_node.node_id} failed to forward message.")

# Overriding receive_message to support tracking
def receive_message_override(self, message, sender):
    print(f"[Receive] Node {self.node_id} received message {message.id} from Node {sender.node_id}")
    self.messages_forwarded[message.id] = message

# Note: Attach this override externally with:
# SensorNode.receive_message = receive_message_override