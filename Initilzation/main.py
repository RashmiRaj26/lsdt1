# main.py

from network import initialize_network
import matplotlib.pyplot as plt
import networkx as nx

# Initialize the network
G, sensor_nodes, sink_node, positions = initialize_network()

# Visualize (optional)
def visualize_network_with_radius(G, sensor_nodes, sink_node, positions, area_size=100):
    plt.figure(figsize=(10, 10))
    nx.draw(G, positions, with_labels=True, node_size=500, node_color='skyblue', font_size=10, font_weight='bold')
    plt.scatter(*sink_node.location, color='red', s=200, label='Sink Node')
    
    for node in sensor_nodes.values():
        circle = plt.Circle(node.location, node.communication_radius, color='orange', fill=False, linestyle='dotted', linewidth=1.5)
        plt.gca().add_artist(circle)

    plt.title('Wireless Sensor Network with Circular Transmission Radius')
    plt.legend()
    plt.xlim(0, area_size)
    plt.ylim(0, area_size)
    plt.axis('equal')
    plt.grid()
    plt.show()

visualize_network_with_radius(G, sensor_nodes, sink_node, positions)
