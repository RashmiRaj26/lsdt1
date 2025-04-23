import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import random
import math
from Initialization.nodeStructure import SensorNode, SinkNode
from simulate import simulate

# ------------------ Helper Functions ------------------
def euclidean_distance(loc1, loc2):
    return math.sqrt((loc1[0] - loc2[0]) ** 2 + (loc1[1] - loc2[1]) ** 2)

def encrypt(data):
    return f"enc({data})"

def decrypt(ciphertext):
    return ciphertext.replace("enc(", "").replace(")", "")

def ET(d, L): 
    return d * 0.1 + L * 0.01  # Simulated energy transmission cost

# ------------------ Step 1 ------------------
def step1_send_query(node_u, message, neighbor_nodes, Du):
    print("\n--- Step 1: Sending Queries ---")
    queries = {}
    for v in neighbor_nodes:
        if v.node_id not in message['path*']:
            alpha_j = random.randint(1, 100)
            query = {
                'IDu': node_u.node_id,
                'g_alpha_j': alpha_j,
                'TS': message['TS']
            }
            queries[v.node_id] = query
            print(f"Query sent from Node {node_u.node_id} to Node {v.node_id}: {query}")
    return queries

# ------------------ Step 2 ------------------
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

# ------------------ Step 3 ------------------
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

# ------------------ Step 4 ------------------
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

# ------------------ Step 5 ------------------
def step5_forward_message(message, selected_node_id):
    print("\n--- Step 5: Forwarding Message ---")
    new_message = message.copy()
    new_message['path*'].append(selected_node_id)
    print(f"Message forwarded to Node {selected_node_id}. Path so far: {new_message['path*']}")
    return new_message

# ------------------ Message Transmission Simulation ------------------
def simulate_message_transmission():
    print("\n--- Simulation Start ---")
    sink = SinkNode(location=(100, 100))
    source_node = SensorNode("n0", (0, 0), 100, 40)
    nodes = [
        SensorNode("n1", (20, 10), 90, 30),
        SensorNode("n2", (40, 60), 85, 40),
        SensorNode("n3", (60, 40), 80, 20),
        SensorNode("n4", (80, 60), 80, 40),
        SensorNode("n5", (0, 20), 100, 35),
        SensorNode("n6", (0, 50), 80, 34),
        SensorNode("n7", (80, 20), 60, 56),
        SensorNode("n8", (40, 20), 80, 58),
        SensorNode("n9", (60, 80), 90, 45),
        SensorNode("n10", (80, 90), 80, 60),
    ]
    all_nodes = {node.node_id: node for node in nodes}
    all_nodes[source_node.node_id] = source_node

    message = {
        'id': 'm1',
        'TS': 123456,
        'path': [],
        'path*': [source_node.node_id]
    }

    current_node = source_node
    hop = 0
    while hop < sink.max_hops:
        print(f"\n--- Hop {hop + 1} ---")
        neighbors = [
            node for node in nodes 
            if node.node_id not in message['path*'] and 
            euclidean_distance(current_node.location, node.location) <= current_node.communication_radius
        ]

        if not neighbors:
            print("No neighbors within range. Breaking the loop.")
            break

        print(f"Current Node: {current_node.node_id}")
        queries = step1_send_query(current_node, message, neighbors, current_node.communication_radius)
        responses = step2_neighbors_respond(queries, sink.location, all_nodes)
        metrics = step3_decrypt_and_collect(responses, queries)
        selected_id = step4_select_relay(metrics, current_node, message, all_nodes, L=100)
        message = step5_forward_message(message, selected_id)
        current_node = all_nodes[selected_id]
        hop += 1

        if euclidean_distance(current_node.location, sink.location) <= current_node.communication_radius:
            message['path*'].append('sink')
            print(f"Message reached the Sink Node!")
            break

    message['final_hop'] = current_node.node_id
    message['total_hops'] = hop + 1
    return {
    'message': message,
    'all_nodes': all_nodes,
    'sink': sink
    }


if __name__ == "__main__":
    result = simulate_message_transmission()
    print("\n--- Simulation Complete ---")
    print("Message transmission path:", result['message']['path*'])
    print("Total hops:", result['message']['total_hops'])
    simulate(result['message']['path*'], result['sink'], result['all_nodes'])
 
