from Initilzation.network import initialize_network
from Initilzation.routing_path import reference_routing_path_initialization
import matplotlib.pyplot as plt
import networkx as nx

# Step 1: Initialize the network
G, sensor_nodes, sink_node, positions = initialize_network()

# Step 2: Initialize routing paths based on the algorithm
reference_routing_path_initialization(G, sensor_nodes, sink_node)

# Step 3: Visualization function with arrows
def visualize_network_with_radius(G, sensor_nodes, sink_node, positions, area_size=100):
    plt.figure(figsize=(10, 10))
    
    # Draw nodes and edges
    nx.draw(G, positions, with_labels=True, node_size=500, node_color='skyblue', font_size=10, font_weight='bold')
    plt.scatter(*sink_node.location, color='red', s=200, label='Sink Node')

    # Draw communication radius
    for node in sensor_nodes.values():
        circle = plt.Circle(node.location, node.communication_radius, color='orange', fill=False, linestyle='dotted', linewidth=1.5)
        plt.gca().add_artist(circle)

    # Draw routing paths as arrows
    for node in sensor_nodes.values():
        if node.routing_paths:
            best_path = min(node.routing_paths, key=len)  # Choose the shortest routing path
            for i in range(len(best_path) - 1):
                src = best_path[i]
                dst = best_path[i + 1]
                x1, y1 = positions[src]
                x2, y2 = positions[dst]
                dx, dy = x2 - x1, y2 - y1
                plt.arrow(x1, y1, dx * 0.85, dy * 0.85,  # Scale to avoid overshooting
                          head_width=1.5, length_includes_head=True, color='green', alpha=0.7)

    plt.title('Wireless Sensor Network with Routing Arrows')
    plt.legend()
    plt.xlim(0, area_size)
    plt.ylim(0, area_size)
    plt.axis('equal')
    plt.grid()
    plt.show()

# Step 4: Visualize the network
visualize_network_with_radius(G, sensor_nodes, sink_node, positions)
