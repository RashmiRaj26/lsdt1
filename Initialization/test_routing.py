import numpy as np
import networkx as nx
from routing_path import initialize_routing
from nodeStructure import SensorNode, SinkNode

# Create a dummy network
def create_dummy_network(num_nodes=5, area_size=100, E0=100, theta=0.5, transmission_range=20):
    G = nx.Graph()
    positions = {
        i: (np.random.uniform(0, area_size), np.random.uniform(0, area_size))
        for i in range(num_nodes)
    }

    sensor_nodes = {}

    for node_id in range(num_nodes):
        initial_energy = np.random.uniform(E0, (1 + theta) * E0)
        communication_radius = np.random.uniform(5, transmission_range)

        sensor_node = SensorNode(node_id, positions[node_id], initial_energy, communication_radius)

        # Initialize expected attributes used by routing
        sensor_node.SM = {
            "neighbors": [],
            "hop": None,
            "R": set(),
            "received_from": None,
            "next_hop": None
        }
        sensor_node.routing_paths = []

        sensor_nodes[node_id] = sensor_node
        G.add_node(node_id, pos=positions[node_id])

    # Add edges between nodes based on transmission range
    for i in range(num_nodes):
        for j in range(i + 1, num_nodes):
            if np.linalg.norm(np.array(positions[i]) - np.array(positions[j])) <= transmission_range:
                G.add_edge(i, j)
                # Update the neighbors of each node
                sensor_nodes[i].SM["neighbors"].append(j)
                sensor_nodes[j].SM["neighbors"].append(i)

    # Initialize Sink Node with an 'id'
    sink_location = (np.random.uniform(0, area_size), np.random.uniform(0, area_size))
    sink_node = SinkNode(location=sink_location)
    sink_node.id = num_nodes  # Assign an ID to the sink node
    sink_node.communication_radius = transmission_range
    sink_node.SM = {
        "PPK": {"Los": sink_location},
        "hop": 0,
        "R": set()
    }

    G.add_node(sink_node.id, pos=sink_node.location)

    return G, sensor_nodes, sink_node


# Function to print routing tables
def print_routing_tables(sensor_nodes):
    for node_id, node in sensor_nodes.items():
        print(f"Node {node_id}:")
        print(f"  Routing Paths: {node.routing_paths}")
        print(f"  State Management: {node.SM}")
        print()

# Main function to initialize the network and print the routing tables
def main():
    G, sensor_nodes, sink_node = create_dummy_network()
    initialize_routing(sink_node, sensor_nodes, G)
    print_routing_tables(sensor_nodes)

if __name__ == "__main__":
    main()
