# network_init.py

import numpy as np
import networkx as nx
from nodeStructure import SensorNode, SinkNode

def initialize_network(num_nodes=20, area_size=100, E0=100, theta=0.5, transmission_range=20, seed=42):
    np.random.seed(seed)

    # Generate random positions
    positions = {
        i: (np.random.uniform(0, area_size), np.random.uniform(0, area_size))
        for i in range(num_nodes)
    }

    # Create graph
    G = nx.Graph()
    sensor_nodes = {}

    # Initialize SensorNodes
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

    # Initialize SinkNode at a random position
    sink_location = (np.random.uniform(0, area_size), np.random.uniform(0, area_size))
    sink_node = SinkNode(location=sink_location)

    return G, sensor_nodes, sink_node, positions
