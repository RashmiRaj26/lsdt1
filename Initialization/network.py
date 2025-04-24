# network_init.py

import numpy as np
import networkx as nx
import random
from sympy import isprime, nextprime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from Initialization.nodeStructure import SensorNode, SinkNode

def initialize_network(num_nodes=20, area_size=100, E0=100, theta=0.5, transmission_range=20, seed=42):
    np.random.seed(seed)

    # Generate random positions for sensor nodes
    positions = {
        i: (np.random.uniform(0, area_size), np.random.uniform(0, area_size))
        for i in range(num_nodes)
    }

    # Create graph and initialize sensor nodes
    G = nx.Graph()
    sensor_nodes = {}

    for node_id in range(num_nodes):
        initial_energy = np.random.uniform(E0, (1 + theta) * E0)
        communication_radius = np.random.uniform(5, transmission_range)
        sensor_node = SensorNode(node_id, positions[node_id], initial_energy, communication_radius)
        sensor_nodes[node_id] = sensor_node
        G.add_node(node_id, pos=positions[node_id], energy=initial_energy, radius=communication_radius)

    # Add edges based on transmission range
    for i in range(num_nodes):
        for j in range(i + 1, num_nodes):
            if np.linalg.norm(np.array(positions[i]) - np.array(positions[j])) <= transmission_range:
                G.add_edge(i, j)

    # 🚨 Create and setup SinkNode with all necessary properties
    sink_location = (np.random.uniform(0, area_size), np.random.uniform(0, area_size))
    sink_node = SinkNode(location=sink_location)

    # Start full initialization inside this function
    Los = sink_location

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

    # Construct PPK and SM directly in the sink_node
    PPK = {
        "Los": Los,
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

    # Add sink node location to the 'positions' dictionary
    sink_id = 'sink'
    positions[sink_id] = sink_node.location
    
    return G, sensor_nodes, sink_node, positions
