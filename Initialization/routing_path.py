# routing_path.py

import numpy as np

def update_routing(node_u, node_v, PPK, sensor_nodes):
    change = 0

    if node_v.SM is None:
        node_v.SM = PPK
        change = 1
        dvs = np.linalg.norm(np.array(node_v.location) - np.array(PPK["Los"]))
        n = len(node_u.routing_paths)
        Pv = PPK["f"](n + 1, dvs) if "f" in PPK else 3  # Default hop value if function is not defined

        node_v.routing_paths = [path + [node_v.id] for path in node_u.routing_paths]
        node_v.SM["hop"] = Pv
    else:
        for path in node_u.routing_paths:
            if path not in node_v.routing_paths:
                if len(path) < node_v.SM["hop"]:
                    node_v.routing_paths.append(path + [node_v.id])
                    change = 1

    if change == 1:
        for neighbor in node_v.neighbors:
            if neighbor != node_u.id:
                update_routing(node_v, sensor_nodes[neighbor], node_v.SM, sensor_nodes)

def initialize_routing(sink_node, sensor_nodes, G):
    for neighbor in G.neighbors(sink_node.id):
        if np.linalg.norm(np.array(sink_node.location) - np.array(sensor_nodes[neighbor].location)) <= sink_node.communication_radius:
            neighbor_node = sensor_nodes[neighbor]
            neighbor_node.routing_paths = [[sink_node.id, neighbor]]  # Sink to node
            neighbor_node.SM = {
                "PPK": sink_node.SM["PPK"],
                "Los": sink_node.location,
                "hop": 3,
                "R": {neighbor}
            }

            for neighbor_of_neighbor in G.neighbors(neighbor):
                if neighbor_of_neighbor != sink_node.id:
                    update_routing(neighbor_node, sensor_nodes[neighbor_of_neighbor], neighbor_node.SM, sensor_nodes)

    for neighbor in G.neighbors(sink_node.id):
        propagate_routing(neighbor, sensor_nodes, G)

def propagate_routing(node_id, sensor_nodes, G):
    node = sensor_nodes[node_id]
    for neighbor in node.neighbors:
        if neighbor != node.id:
            update_routing(node, sensor_nodes[neighbor], node.SM, sensor_nodes)
