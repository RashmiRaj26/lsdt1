from Initialization.network import initialize_network
from Initialization.routing_path import initialize_routing
from Message_encryption.encryption import encrypt_data, decrypt_data
from Initialization.network import initialize_network
import matplotlib.pyplot as plt
import networkx as nx
import base64
from Original_data_recovery.original_data import recover_original_data
from Message_encryption.share_generation import generate_shares
from Message_Transmission.msgtrans import simulate_message_transmission
from Message_Transmission.simulate import simulates
import random
# Optional: allow marking a node malicious for testing
from Message_Transmission.malicious_node_management import mark_node_as_malicious
from Message_Transmission import msgtrans

# Toggle verbose diagnostics in the message transmission module (set True to see per-query prints)
VERBOSE_MSGTRANS = False
msgtrans.DEBUG = VERBOSE_MSGTRANS

G, sensor_nodes, sink_node, positions = initialize_network(num_nodes=30)

# --- Malicious node configuration (toggle for tests) ---
# Set to True to mark a node malicious before sending shares
ENABLE_MALICIOUS_TEST = True
MALICIOUS_NODE_ID = 'node5'  # change as needed
MALICIOUS_BEHAVIOR = 'no_response'  # 'no_response' or 'delay'
MALICIOUS_DELAY = 8.0  # seconds, only used for 'delay'

if ENABLE_MALICIOUS_TEST:
    if MALICIOUS_NODE_ID in sensor_nodes:
        mark_node_as_malicious(sensor_nodes[MALICIOUS_NODE_ID], behavior=MALICIOUS_BEHAVIOR, delay=MALICIOUS_DELAY)
    else:
        print(f"Warning: {MALICIOUS_NODE_ID} not found in sensor_nodes; cannot mark malicious")

message = input("Enter message to encrypt and send to sink node: ")

encrypted = encrypt_data(message, sink_node)

routing_table = {
    "node0": ["node1", "node5", "node13"]
}

t=len(routing_table["node0"])-1

shares = generate_shares(encrypted, t, routing_table, "node0")
print(" ")
for i in range(3):
    print(f"\n================== Transmitting share {i + 1} ==================")
    # pass the initialized network so energy changes persist across shares
    result = simulate_message_transmission(sensor_nodes=sensor_nodes, sink=sink_node, positions=positions)
    print("\n--- Simulation Complete ---")
    print("Message transmission path:", result['message']['path*'])
    print("Total hops:", result['message']['total_hops'])

    color = (random.random(), random.random(), random.random())  # RGB
    simulates(result['message']['path*'], result['sink'], result['all_nodes'], delay=1.5, color=color, share_number=i+1)

decrypted = recover_original_data(shares,sink_node,"node0",routing_table,sink_node.private_key)
print("original data is: ",decrypted)
