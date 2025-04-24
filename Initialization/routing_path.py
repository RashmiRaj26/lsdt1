import numpy as np

def f(n, d):
    return n + d  

def distance(a, b):
    return np.linalg.norm(np.array(a) - np.array(b))

def reference_routing_path_initialization(G, sensor_nodes, sink_node):
    PPK = "public_params_example"
    sink_id = 'sink'

    G.add_node(sink_id, pos=sink_node.location)
    frontier = []

    for node_id, sensor in sensor_nodes.items():
        d = distance(sensor.location, sink_node.location)
        if d <= sensor.communication_radius:
            G.add_edge(sink_id, node_id)
            path = [[sink_id, node_id]]
            sensor.routing_paths = path
            sensor.Pv = f(1, d)
            sensor.PPK = PPK
            frontier.append((sink_id, node_id, path))

    visited = set()

    while frontier:
        u, v, Tu = frontier.pop(0)
        node_v = sensor_nodes[v]
        change = False

        if not hasattr(node_v, 'routing_paths') or not node_v.routing_paths:
            dvs = distance(sink_node.location, node_v.location)
            max_hops = max(len(p) - 1 for p in Tu)
            node_v.Pv = f(max_hops + 1, dvs)
            node_v.PPK = PPK
            node_v.routing_paths = [p + [v] for p in Tu]
            change = True
        else:
            new_paths = []
            for p in Tu:
                if p not in node_v.routing_paths and len(p) < node_v.Pv:
                    new_paths.append(p + [v])
            if new_paths:
                node_v.routing_paths.extend(new_paths)
                change = True

        if change or (u, v) not in visited:
            visited.add((u, v))
            for neighbor in G.neighbors(v):
                if neighbor != u and isinstance(neighbor, int):
                    frontier.append((v, neighbor, node_v.routing_paths))

    G.remove_node(sink_id)