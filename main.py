from Initialization.network import initialize_network
from Initialization.routing_path import reference_routing_path_initialization
from Message_encryption.encryption import encrypt_data, decrypt_data
import matplotlib.pyplot as plt
import networkx as nx
import base64
from Original_data_recovery.original_data import recover_original_data
from Message_encryption.share_generation import generate_shares
# Step 1: Initialize the network with 10 sensor nodes
G, sensor_nodes, sink_node, positions = initialize_network(num_nodes=10)

# Step 2: Generate sink node keys
# sink_node.generate_keys()

# Step 3: Initialize routing paths based on the algorithm
# reference_routing_path_initialization(G, sensor_nodes, sink_node)

# Step 4: Take user input message
message = int(input("Enter message to encrypt and send to sink node: "))

encrypted = encrypt_data(message, sink_node)
print("\n🔒 Encrypted Message:")
print(encrypted)

# ciphertext = base64.b64decode(encrypted)

# Step 5: Sink node decrypts the message
decrypted = decrypt_data(sink_node, encrypted)
print("\n🔓 Decrypted Message at Sink Node:")
print(decrypted)

routing_table = {
    "node1": ["node2", "node3", "node4", "node5", "node6"]
}

t=4

shares = generate_shares(encrypted, t, routing_table, "node1")


for share in shares:
    print(f"Share {share['index']}: {share['share']}\n  Hash: {share['hash']}\n  Path: {share['path']}\n")

# decrypted = recover_original_data(shares,sink_node,"node1",routing_table,sink_node.private_key)


# Step 6: Visualize the network
# def visualize_network_with_radius(G, sensor_nodes, sink_node, positions, area_size=100):
#     plt.figure(figsize=(10, 10))
    
#     # Draw nodes and edges
#     nx.draw(G, positions, with_labels=True, node_size=500, node_color='skyblue', font_size=10, font_weight='bold')
#     plt.scatter(*sink_node.location, color='red', s=200, label='Sink Node')

#     # Draw communication radius
#     for node in sensor_nodes.values():
#         circle = plt.Circle(node.location, node.communication_radius, color='orange', fill=False, linestyle='dotted', linewidth=1.5)
#         plt.gca().add_artist(circle)

#     # Draw routing paths as arrows
#     for node in sensor_nodes.values():
#         if node.routing_paths:
#             best_path = min(node.routing_paths, key=len)  # Choose the shortest routing path
#             for i in range(len(best_path) - 1):
#                 src = best_path[i]
#                 dst = best_path[i + 1]
#                 x1, y1 = positions[src]
#                 x2, y2 = positions[dst]
#                 dx, dy = x2 - x1, y2 - y1
#                 plt.arrow(x1, y1, dx * 0.85, dy * 0.85,
#                           head_width=1.5, length_includes_head=True, color='green', alpha=0.7)

#     plt.title('Wireless Sensor Network with Routing Arrows')
#     plt.legend()
#     plt.xlim(0, area_size)
#     plt.ylim(0, area_size)
#     plt.axis('equal')
#     plt.grid()
#     plt.show()

# visualize_network_with_radius(G, sensor_nodes, sink_node, positions)
