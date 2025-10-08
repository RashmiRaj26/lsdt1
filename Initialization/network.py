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
        (10, 20), (20, 35), (76, 75), (40, 30), (50, 55),
        (25, 34), (70, 60), (80, 20), (90, 40), (60, 42),
        (25, 55), (35, 65), (89, 15), (48, 49), (65, 75),
        (75, 25), (85, 50), (65, 70), (60, 85), (80, 90),
        # 10 additional predefined positions to allow up to 30 nodes
        (15, 10), (5, 50), (55, 15), (95, 70), (30, 10),
        (45, 80), (10, 75), (72, 45), (58, 30), (22, 70)
    ]
    # if caller asks for more nodes than predefined positions, generate positions
    # Place generated nodes so that each node (including previously placed ones)
    # has at least 2 neighbors within transmission_range where possible (best-effort).
    positions = {}
    if num_nodes <= len(predefined_positions):
        positions = {i: predefined_positions[i] for i in range(num_nodes)}
    else:
        # take predefined positions first
        for i, p in enumerate(predefined_positions):
            positions[i] = p

        # helper: count neighbors within transmission_range among current positions
        def neighbor_count(candidate, existing_positions, trange):
            import math
            cnt = 0
            cx, cy = candidate
            for _, (x, y) in existing_positions.items():
                if math.hypot(cx - x, cy - y) <= trange:
                    cnt += 1
            return cnt

        # generate remaining positions with retries to ensure at least 2 neighbors
        max_attempts_per_node = 200
        for i in range(len(predefined_positions), num_nodes):
            placed = False
            attempts = 0
            while not placed and attempts < max_attempts_per_node:
                attempts += 1
                cand = (float(np.random.uniform(0, area_size)), float(np.random.uniform(0, area_size)))
                # require that the candidate has >=2 neighbors among already placed nodes
                if neighbor_count(cand, positions, transmission_range) >= 2:
                    positions[i] = (int(cand[0]), int(cand[1]))
                    placed = True
                    break
                # if not enough neighbors yet, as a fallback allow placement near an existing node
                if attempts % 20 == 0:
                    # pick a random existing node and place candidate near it within trange/2
                    import math, random as _rnd
                    base_idx = _rnd.choice(list(positions.keys()))
                    bx, by = positions[base_idx]
                    angle = _rnd.uniform(0, 2 * math.pi)
                    radius = _rnd.uniform(1, transmission_range / 2.0)
                    cand = (bx + radius * math.cos(angle), by + radius * math.sin(angle))
                    # clamp into area
                    cand = (max(0.0, min(area_size, cand[0])), max(0.0, min(area_size, cand[1])))
                    if neighbor_count(cand, positions, transmission_range) >= 2:
                        positions[i] = (int(cand[0]), int(cand[1]))
                        placed = True
                        break

            # if we failed to find a spot with >=2 neighbors after many attempts,
            # accept the last candidate (best-effort) to avoid infinite loops
            if not placed:
                # final fallback: place uniformly at random and accept it
                cand = (int(np.random.uniform(0, area_size)), int(np.random.uniform(0, area_size)))
                positions[i] = cand

    G = nx.Graph()
    sensor_nodes = {}

    for node_id, pos in positions.items():
        initial_energy = np.random.uniform(E0, (1 + theta) * E0)
        # Use the global transmission_range as the per-node communication radius
        # to avoid very small random radii that make nodes isolated. This ensures
        # neighbor discovery is consistent with how graph edges are constructed
        # (edges use transmission_range). If desired we can add small jitter.
        communication_radius = transmission_range
        sensor_node = SensorNode(node_id, pos, initial_energy, communication_radius)
        sensor_nodes[node_id] = sensor_node
        G.add_node(node_id, pos=pos, energy=initial_energy, radius=communication_radius)
    for i in range(num_nodes):
        for j in range(i + 1, num_nodes):
            if np.linalg.norm(np.array(positions[i]) - np.array(positions[j])) <= transmission_range:
                G.add_edge(i, j)
    sink_location = (80, 80)  
    sink_node = SinkNode(location=sink_location)
    # set the canonical node_id used across the codebase
    sink_node.node_id = 'sink'
    # maintain backward-compatible attribute expected in other modules
    sink_node.id = sink_node.node_id
    sink_node.communication_radius = transmission_range
    G.add_node(sink_node.node_id, pos=sink_node.location)
    positions[sink_node.node_id] = sink_node.location
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
