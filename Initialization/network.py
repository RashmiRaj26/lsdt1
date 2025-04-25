import numpy as np
import networkx as nx
import random
from sympy import isprime, nextprime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Initialization.nodeStructure import SensorNode, SinkNode
from Initialization.routing_path import initialize_routing

def initialize_network(num_nodes=20, area_size=100, E0=100, theta=0.5, transmission_range=30, seed=42):
    np.random.seed(seed)
    predefined_positions = [
        (10, 20), (20, 35), (0, 40), (40, 30), (50, 55),
        (25, 34), (70, 60), (80, 20), (90, 40), (60, 42),
        (25, 55), (35, 65), (89, 15), (90, 35), (65, 75),
        (75, 25), (85, 50), (20, 80), (60, 85), (80, 90)
    ]
    if len(predefined_positions) < num_nodes:
        raise ValueError("Not enough predefined positions. Add more to the list.")
    positions = {i: predefined_positions[i] for i in range(num_nodes)}

    G = nx.Graph()
    sensor_nodes = {}

    for node_id, pos in positions.items():
        initial_energy = np.random.uniform(E0, (1 + theta) * E0)
        communication_radius = np.random.uniform(5, transmission_range)
        sensor_node = SensorNode(node_id, pos, initial_energy, communication_radius)
        sensor_nodes[node_id] = sensor_node
        G.add_node(node_id, pos=pos, energy=initial_energy, radius=communication_radius)
    for i in range(num_nodes):
        for j in range(i + 1, num_nodes):
            if np.linalg.norm(np.array(positions[i]) - np.array(positions[j])) <= transmission_range:
                G.add_edge(i, j)
    sink_location = (61, 55)  
    sink_node = SinkNode(location=sink_location)
    sink_node.id = 'sink'
    sink_node.communication_radius = transmission_range  
    G.add_node(sink_node.id, pos=sink_node.location)
    positions[sink_node.id] = sink_node.location
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    sink_node.private_key = private_key
    sink_node.public_key = public_key

    λ = 0.5
    hash_function = hashes.SHA256()

    def max_hop_calculator(n):
        import math
        return int(math.log2(n)) + 1

    def generate_large_prime(bits=256):
        prime = random.getrandbits(bits)
        while not isprime(prime):
            prime = nextprime(prime)
        return prime

    def generate_generator(q):
        for g in range(2, q):
            if pow(g, 2, q) != 1:
                return g
        return 2

    q = generate_large_prime()
    g = generate_generator(q)

    PPK = {
        "Los": sink_location,
        "pk": public_key,
        "f": max_hop_calculator,
        "λ": λ,
        "H": hash_function.name,
        "Gq": q,
        "g": g
    }

    sink_node.SM = {
        "PPK": PPK,
        "hop": 0,
        "R": set()
    }
    initialize_routing(sink_node, sensor_nodes, G)

    return G, sensor_nodes, sink_node, positions
