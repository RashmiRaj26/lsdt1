import time
import hashlib
from collections import defaultdict
import threading

import math

def euclidean_distance(loc1, loc2):
    return math.sqrt((loc1[0] - loc2[0])**2 + (loc1[1] - loc2[1])**2)

def send_message(u, v, message):
    print(f"[SEND] {u.node_id} -> {v.node_id} (MSG id={message['id']})")
    # energy cost per send (constant)
    COST_PER_SEND = 10.0

    if not hasattr(u, 'last_sent_time'):
        u.last_sent_time = {}
    u.last_sent_time[v.node_id] = time.time()

    # deduct energy from sender via consume_energy if available
    if hasattr(u, 'consume_energy'):
        try:
            u.consume_energy(COST_PER_SEND)
            print(f"Node {u.node_id} energy reduced by {COST_PER_SEND}. New energy: {getattr(u, 'initial_energy', 'unknown')}")
        except Exception:
            print(f"Warning: couldn't update energy for Node {u.node_id}")

    # Deliver message to receiver unless the receiver is malicious and configured
    # to not respond within the TD window.
    def _deliver():
        v.last_received_message = message.copy()

    # If the receiver is marked malicious, it can either not respond at all or
    # delay the response beyond the TD window.
    if getattr(v, 'malicious', False):
        behavior = getattr(v, 'malicious_behavior', 'no_response')
        if behavior == 'no_response':
            # do not set last_received_message -> forward_and_monitor will time out
            print(f"Node {v.node_id} is malicious (no_response): not delivering message to it")
        elif behavior == 'delay':
            delay = getattr(v, 'malicious_response_delay', None)
            if delay is None:
                # default: delay longer than typical TD so it times out
                delay = 10.0
            print(f"Node {v.node_id} is malicious (delay): will deliver after {delay}s")
            t = threading.Thread(target=lambda: (time.sleep(delay), _deliver()), daemon=True)
            t.start()
        else:
            # unknown behavior - deliver normally but warn
            print(f"Warning: unknown malicious behavior '{behavior}' for Node {v.node_id}. Delivering normally.")
            _deliver()
    else:
        _deliver()

suspicious_nodes = set()
node_reputation = defaultdict(lambda: {'gamma': 1, 'k': 0, 'pv': 1.0})


def compute_hash(data):
    
    return hashlib.sha256(str(data).encode()).hexdigest()


def forward_and_monitor(u, v, message, TD, all_nodes, sink):
   
    
    original_signature = (message['id'], message['TS'], tuple(message['path*']))
    message_hash = compute_hash(original_signature)
    message['hash'] = message_hash

    
    send_message(u, v, message)

    time.sleep(TD)

    response = getattr(v, 'last_received_message', None)
    if not response:
        print(f"Node {v.node_id} did not respond within TD. Marked as suspicious.")
        mark_suspicious(u, v, message, sink, all_nodes)
        return

    returned_signature = (response.get('id'), response.get('TS'), tuple(response.get('path*', [])))
    returned_hash = compute_hash(returned_signature)

    if returned_hash != message_hash:
        print(f"Node {v.node_id} sent tampered message. Marked as suspicious.")
        mark_suspicious(u, v, message, sink, all_nodes)


def mark_suspicious(u, v, message, sink, all_nodes):
    suspicious_nodes.add(v.node_id)
    anomaly_report = {
        "type": "Anomaly",
        "IDv": v.node_id,
        "Lov": v.location,
        "TS": message['TS']
    }
    # forward the anomaly report to the sink for logging/routing
    forward_report_to_sink(u, anomaly_report, v, all_nodes, sink)
    # update reputation immediately based on this single report and broadcast
    try:
        update_reputation(sink, [anomaly_report])
        broadcast_reputation_updates()
    except Exception as e:
        print(f"Warning: failed to update/broadcast reputations: {e}")


def forward_report_to_sink(start_node, report, avoid_node, all_nodes, sink):
    
    current_node = start_node
    path = [current_node.node_id]
    while current_node and current_node.node_id != 'sink':
        neighbors = [n for n in all_nodes.values() if n.node_id not in path and n.node_id != avoid_node.node_id and 
                     euclidean_distance(current_node.location, n.location) <= current_node.communication_radius]
        if not neighbors:
            print("No route to sink available avoiding suspicious node.")
            return
        next_node = min(neighbors, key=lambda x: euclidean_distance(x.location, sink.location))
        path.append(next_node.node_id)
        current_node = next_node
    print(f"Anomaly report sent to Sink via path: {path}")


def update_reputation(sink, reports):
    for report in reports:
        node_id = report['IDv']
        node_reputation[node_id]['gamma'] += 1
        node_reputation[node_id]['k'] += 1
        gamma = node_reputation[node_id]['gamma']
        k = node_reputation[node_id]['k']
        node_reputation[node_id]['pv'] = gamma ** (-k)


def broadcast_reputation_updates():
    print("Broadcasting updated reputations:")
    for node_id, rep in node_reputation.items():
        print(f"Node {node_id}: Reputation pv = {rep['pv']:.4f}")
    print("completed!")


def mark_node_as_malicious(node, behavior='no_response', delay=None):
    """
    Mark a node as malicious.

    Parameters:
    - node: SensorNode instance to mark
    - behavior: 'no_response' (doesn't set last_received_message) or 'delay' (delivers after `delay` seconds)
    - delay: seconds to wait before delivering the message (only for 'delay')
    """
    setattr(node, 'malicious', True)
    setattr(node, 'malicious_behavior', behavior)
    if delay is not None:
        setattr(node, 'malicious_response_delay', float(delay))
    print(f"Node {node.node_id} marked malicious: behavior={behavior}, delay={delay}")
