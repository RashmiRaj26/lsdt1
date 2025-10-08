import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import random
import math
import time
from Initialization.network import initialize_network
from Initialization.nodeStructure import SensorNode, SinkNode

from Message_Transmission.malicious_node_management import forward_and_monitor 

def euclidean_distance(loc1, loc2):
    return math.sqrt((loc1[0] - loc2[0]) ** 2 + (loc1[1] - loc2[1]) ** 2)

def send_message(sender, receiver, message):
    print(f"[SEND] {sender.node_id} -> {receiver.node_id} (MSG id={message['id']})")
    # energy cost per send (constant)
    COST_PER_SEND = 10.0

    # record send timestamp
    if not hasattr(sender, 'last_sent_time'):
        sender.last_sent_time = {}
    sender.last_sent_time[receiver.node_id] = time.time()

    # deduct energy from sender if attribute exists
    # deduct energy from sender via consume_energy if available
    if hasattr(sender, 'consume_energy'):
        try:
            sender.consume_energy(COST_PER_SEND)
            print(f"Node {sender.node_id} energy reduced by {COST_PER_SEND}. New energy: {getattr(sender, 'initial_energy', 'unknown')}")
        except Exception:
            print(f"Warning: couldn't update energy for Node {sender.node_id}")

    # deliver message copy to receiver
    receiver.last_received_message = message.copy()

def encrypt(data):
    return f"enc({data})"

def decrypt(ciphertext):
    return ciphertext.replace("enc(", "").replace(")", "")

def ET(d, L): 
    return d * 0.1 + L * 0.01

def step1_send_query(node_u, message, neighbor_nodes, Du):
    print("\n--- Step 1: Sending Queries ---")
    queries = {}
    for v in neighbor_nodes:
        # ensure both nodes can reach each other: distance <= min(u.radius, v.radius)
        dist_uv = euclidean_distance(node_u.location, v.location)
        effective_range = min(node_u.communication_radius, v.communication_radius)
        if v.node_id not in message['path*'] and dist_uv <= effective_range:
            alpha_j = random.randint(1, 100)
            query = {
                'IDu': node_u.node_id,
                'g_alpha_j': alpha_j,
                'TS': message['TS']
            }
            queries[v.node_id] = query
            print(f"Query sent from Node {node_u.node_id} to Node {v.node_id}: {query}")
    return queries

def step2_neighbors_respond(queries, sink_location, all_nodes):
    print("\n--- Step 2: Neighbors Responding ---")
    responses = {}
    for v_id, q in queries.items():
        v = all_nodes[v_id]
        beta_j = random.randint(1, 100)
        g_beta_j = beta_j
        g_alpha_beta_j = q['g_alpha_j'] * beta_j

        dvjs = euclidean_distance(v.location, sink_location)
        ciphertext = encrypt(f"{v.node_id}|{v.initial_energy}|{dvjs}|{q['TS']}|{g_alpha_beta_j}")
        response = {
            'ciphertext': ciphertext,
            'g_beta_j': g_beta_j
        }
        responses[v_id] = response
        print(f"Response from Node {v.node_id}: {response}")
    return responses

def step3_decrypt_and_collect(responses, queries):
    print("\n--- Step 3: Decrypting and Collecting Responses ---")
    metrics = {}
    for v_id, res in responses.items():
        decrypted = decrypt(res['ciphertext'])
        parts = decrypted.split('|')
        metrics[v_id] = {
            'id': parts[0],
            'energy': float(parts[1]),
            'dvjs': float(parts[2]),
            'TS': parts[3]
        }
        print(f"Decrypted Data from Node {v_id}: {metrics[v_id]}")
    return metrics

def step4_select_relay(metrics, node_u, message, all_nodes, L, lambda_val=2):
    print("\n--- Step 4: Selecting Relay Node ---")
    IF_values = {}
    for v_id, m in metrics.items():
        v = all_nodes[v_id]
        duvj = euclidean_distance(node_u.location, v.location)

        pvj = 1
        pa = lambda_val if v_id in message['path'] else 1
        energy_term = m['energy'] / ET(duvj, L)
        distance_term = 1 / (m['dvjs'] ** 2)
        IF = pvj * pa * energy_term * distance_term

        IF_values[v_id] = IF
        print(f"Node {v_id}: IF value = {IF}")

    best_node = max(IF_values, key=IF_values.get)
    print(f"Selected Relay Node: {best_node} with IF value: {IF_values[best_node]}")
    return best_node

def step5_forward_message(message, selected_node_id):
    print("\n--- Step 5: Forwarding Message ---")
    new_message = message.copy()
    new_message['path*'].append(selected_node_id)
    print(f"Message forwarded to Node {selected_node_id}. Path so far: {new_message['path*']}")
    return new_message

def simulate_message_transmission(sensor_nodes=None, sink=None, positions=None):
    print("\n--- Simulation Start ---")

    # allow caller to pass an existing network so node energy persists across multiple shares
    if sensor_nodes is None or sink is None or positions is None:
        G, sensor_nodes, sink, positions = initialize_network()

    source_node = list(sensor_nodes.values())[0]
    all_nodes = sensor_nodes.copy()
    # add sink to all_nodes if not present
    if getattr(sink, 'node_id', None) not in all_nodes:
        all_nodes[sink.node_id] = sink

    message = {
        'id': 'm1',
        'TS': 123456,
        'path': [],
        'path*': [source_node.node_id]
    }

    current_node = source_node
    hop = 0
    # Allow paths up to the number of sensor nodes so routes have room to reach sink.
    # Keep the original function as a lower bound for backward compatibility.
    try:
        lower_bound = sink.SM['PPK']['f'](len(sensor_nodes))
    except Exception:
        lower_bound = 0
    max_hops = max(lower_bound, len(sensor_nodes))

    while hop < max_hops:
        print(f"\n--- Hop {hop + 1} ---")
        print(f"Current Node: {current_node.node_id}")
        
        dist_to_sink = euclidean_distance(current_node.location, sink.location)
        print(f"Distance to sink: {dist_to_sink}, Comm range: {current_node.communication_radius}")

        if dist_to_sink <= current_node.communication_radius:
            print(f"Sink is within range of Node {current_node.node_id}. Forwarding message to sink.")
            message['path*'].append('sink')
            print("Message reached the Sink Node!")
            break 

        
        # neighbor is valid only if both nodes are within each other's communication radii
        neighbors = []
        for node_id, node in all_nodes.items():
            if node_id == current_node.node_id or node_id in message['path*']:
                continue
            dist = euclidean_distance(current_node.location, node.location)
            if dist <= min(current_node.communication_radius, node.communication_radius):
                neighbors.append(node)
        # Detailed diagnostics: list candidates and exclusions
        candidates = []
        exclusions = []
        for node_id, node in all_nodes.items():
            if node_id == current_node.node_id:
                continue
            dist = euclidean_distance(current_node.location, node.location)
            can_reach = dist <= min(current_node.communication_radius, node.communication_radius)
            if can_reach:
                if node_id in message['path*']:
                    exclusions.append((node_id, dist))
                else:
                    candidates.append((node_id, dist))
        if candidates:
            print(f"Candidates within mutual range (not in path*): {[ (n,d) for n,d in candidates ]}")
        if exclusions:
            print(f"Reachable but excluded (in path*): {[ (n,d) for n,d in exclusions ]}")

        if not neighbors:
            print("No neighbors within range. Diagnostic info:")
            # show nearby nodes with distances and their radii for debugging
            for node_id, node in all_nodes.items():
                if node_id == current_node.node_id:
                    continue
                dist = euclidean_distance(current_node.location, node.location)
                print(f" - Node {node_id}: dist={dist:.3f}, node.radius={node.communication_radius}, cur.radius={current_node.communication_radius}")
            dist_sink = euclidean_distance(current_node.location, sink.location)
            print(f" - Distance to sink: {dist_sink:.3f}, sink.radius={sink.communication_radius}")
            print("Breaking the loop.")
            break

        queries = step1_send_query(current_node, message, neighbors, current_node.communication_radius)
        responses = step2_neighbors_respond(queries, sink.location, all_nodes)
        metrics = step3_decrypt_and_collect(responses, queries)
        selected_id = step4_select_relay(metrics, current_node, message, all_nodes, L=100)

        v = all_nodes[selected_id]
        # use forward_and_monitor to perform the actual send and monitoring (it calls send_message)
        forward_and_monitor(current_node, v, message, TD=1.0, all_nodes=all_nodes, sink=sink)

        message = step5_forward_message(message, selected_id)
        current_node = all_nodes[selected_id]
        hop += 1

    message['final_hop'] = current_node.node_id
    message['total_hops'] = hop + 1
    if hop >= max_hops:
        print(f"Stopped because max_hops={max_hops} reached. Consider increasing max_hops or adjusting routing.")
    
    return {
        'message': message,
        'all_nodes': all_nodes,
        'sink': sink
    }

# # ------------------ Main Simulation Loop ------------------
# if __name__ == "__main__":
#     for i in range(3):
#         print(f"\n================== Transmitting share {i + 1} ==================")
#         result = simulate_message_transmission()
#         print("\n--- Simulation Complete ---")
#         print("Message transmission path:", result['message']['path*'])
#         print("Total hops:", result['message']['total_hops'])

#         color = (random.random(), random.random(), random.random())  # RGB
        # simulate(result['message']['path*'], result['sink'], result['all_nodes'], delay=1.5, color=color, share_number=i+1)