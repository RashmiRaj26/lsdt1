from Initialization.network import initialize_network
from Message_Transmission.msgtrans import simulate_message_transmission

# initialize once
G, sensor_nodes, sink_node, positions = initialize_network(num_nodes=30)

print("Initial energies:")
for nid, node in sensor_nodes.items():
    print(f"Node {nid}: {node.initial_energy}")

for i in range(3):
    print(f"\n=== Transmitting share {i+1} ===")
    result = simulate_message_transmission(sensor_nodes=sensor_nodes, sink=sink_node, positions=positions)
    print("Energies after share:")
    for nid, node in result['all_nodes'].items():
        if hasattr(node, 'initial_energy'):
            print(f"Node {nid}: {node.initial_energy}")

print("Done")
