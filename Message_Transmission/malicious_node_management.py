# Malicious Node Management based on Section IV-C and V-C.2

def detect_malicious_node(last_node, current_node, message, timestamp, tampered=False, timeout=False):
    """
    Node `last_node` monitors the behavior of `current_node` after forwarding a message.
    """
    suspicious = False
    reason = None

    if timeout:
        suspicious = True
        reason = "Timeout: message not forwarded in time"
    elif tampered:
        suspicious = True
        reason = "Message hash mismatch (tampered)"

    if suspicious:
        print(f"[!] Node {current_node.node_id} marked as suspicious by Node {last_node.node_id} due to: {reason}")
        report = {
            "type": "Anomaly",
            "reporting_node": last_node.node_id,
            "suspect_node": current_node.node_id,
            "location": current_node.location,
            "timestamp": timestamp
        }
        return report
    return None


def update_reputation(sink_node, reports, all_nodes):
    """
    Sink receives malicious node reports and updates reputation values accordingly.
    """
    print("\n⚠️  Sink Node Reviewing Reports")
    reputation_updates = {}
    
    for report in reports:
        v_id = report["suspect_node"]
        v_node = next(n for n in all_nodes if n.node_id == v_id)

        # Increase anomaly score
        if not hasattr(v_node, "gamma"):
            v_node.gamma = 1
        if not hasattr(v_node, "k"   ):
            v_node.k = 1
        else:
            v_node.k += 1

        v_node.gamma += 1
        v_node.reputation = v_node.gamma ** (-v_node.k)

        print(f"[Update] Node {v_node.node_id} marked suspicious {v_node.k} time(s), new reputation: {v_node.reputation:.4f}")
        reputation_updates[v_id] = v_node.reputation

    # Broadcast updates
    print("\n📡 Broadcasting updated reputations to all nodes...")
    for node in all_nodes:
        for neighbor in node.neighbors:
            if neighbor.node_id in reputation_updates:
                neighbor.reputation = reputation_updates[neighbor.node_id]
                print(f"  Node {node.node_id} updated reputation of Neighbor {neighbor.node_id} to {neighbor.reputation:.4f}")
