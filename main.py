from Initialization.network import initialize_network
from Initialization.routing_path import initialize_routing
from Message_encryption.encryption import encrypt_data, decrypt_data
import matplotlib.pyplot as plt
import networkx as nx
import base64
from Original_data_recovery.original_data import recover_original_data
from Message_encryption.share_generation import message_generation_and_sharing
from Message_Transmission.msgtrans import simulate_message_transmission
from Message_Transmission.simulate import simulates
import random
# Optional: allow marking a node malicious for testing
from Message_Transmission.malicious_node_management import mark_node_as_malicious
from Message_Transmission import msgtrans

# Toggle verbose diagnostics in the message transmission module (set True to see per-query prints)
VERBOSE_MSGTRANS = False
msgtrans.DEBUG = VERBOSE_MSGTRANS

G, sensor_nodes, sink_node, positions, routing_table = initialize_network(num_nodes=30)
print("Sink node:", sink_node.node_id)
print("Sink neighbors:", list(G.neighbors(sink_node.node_id)))
# print clean routing table
# print("\n========= FINAL ROUTING TABLE =========")
# for node_id, info in routing_table.items():
#     P = info["P"]
#     paths = info["paths"]
#     print(f"\nNode {node_id} → Max hops (P): {P}")
#     if paths:
#         for idx, p in enumerate(paths, 1):
#             print(f"   Path {idx}: {p}")
#     else:
#         print("   No paths found")

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

# message = input("Enter message to encrypt and send to sink node: ")

# encrypted = encrypt_data(message, sink_node)
# Determine a source node (first sensor node) and build routing candidates for shares
source_id = list(sensor_nodes.keys())[0]

# routing_table entries from initialize_routing use the form: routing_table[node_id] = {"paths": [...], "P": ...}
share_candidates = []
if source_id in routing_table and isinstance(routing_table[source_id], dict) and routing_table[source_id].get('paths'):
    for p in routing_table[source_id]['paths']:
        # path format is [src, next_hop, ..., 'sink']
        if len(p) > 1:
            share_candidates.append(p[1])

# deduplicate while preserving order
seen = set()
share_candidates = [x for x in share_candidates if not (x in seen or seen.add(x))]

# ensure we have at least 4 candidates; if not, supplement with graph neighbors
if len(share_candidates) < 4:
    for nbr in G.neighbors(source_id):
        if nbr not in share_candidates and nbr != source_id:
            share_candidates.append(nbr)
        if len(share_candidates) >= 4:
            break

# if still not enough, fallback to first sensor node ids
if len(share_candidates) < 4:
    for nid in sensor_nodes.keys():
        if nid not in share_candidates and nid != source_id:
            share_candidates.append(nid)
        if len(share_candidates) >= 4:
            break

# Desired total shares to split into (user request). generate_shares returns t+1 packets,
# so to get DESIRED_TOTAL_SHARES total packets set t = DESIRED_TOTAL_SHARES - 1
DESIRED_TOTAL_SHARES = 4

# Prepare routing candidates: ensure at least DESIRED_TOTAL_SHARES candidates are available
routing_for_shares = {source_id: share_candidates[:DESIRED_TOTAL_SHARES]}
if len(routing_for_shares[source_id]) < DESIRED_TOTAL_SHARES:
    # supplement with neighbors or other nodes until we have enough
    extras = []
    for nbr in G.neighbors(source_id):
        if nbr not in routing_for_shares[source_id] and nbr != source_id:
            extras.append(nbr)
        if len(routing_for_shares[source_id]) + len(extras) >= DESIRED_TOTAL_SHARES:
            break
    for e in extras:
        routing_for_shares[source_id].append(e)

# final fallback: fill from sensor node ids
if len(routing_for_shares[source_id]) < DESIRED_TOTAL_SHARES:
    for nid in sensor_nodes.keys():
        if nid not in routing_for_shares[source_id] and nid != source_id:
            routing_for_shares[source_id].append(nid)
        if len(routing_for_shares[source_id]) >= DESIRED_TOTAL_SHARES:
            break

# Set t so generate_shares will produce DESIRED_TOTAL_SHARES packets
t = DESIRED_TOTAL_SHARES - 1
shares = message_generation_and_sharing(t)
print(" ")
for i in range(DESIRED_TOTAL_SHARES):
    print(f"\n================== Transmitting share {i + 1} ==================")
    # pass the initialized network so energy changes persist across shares
    result = simulate_message_transmission(sensor_nodes=sensor_nodes, sink=sink_node, positions=positions)
    print("\n--- Simulation Complete ---")
    print("Message transmission path:", result['message']['path*'])
    
    print("Total hops:", result['message']['total_hops'])

    color = (random.random(), random.random(), random.random())  # RGB
    simulates(result['message']['path*'], result['sink'], result['all_nodes'], delay=1.5, color=color, share_number=i+1)

decrypted = recover_original_data(shares, sink_node, source_id, routing_for_shares, sink_node.private_key)
print("original data is: ",decrypted)
