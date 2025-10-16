# Initialization/routing_path.py
import math
from collections import deque

def initialize_routing(sink_node, sensor_nodes, G):
    """
    Initialize multi-path routing for all sensor nodes based on the
    Maximum P-hop routing broadcast algorithm described in your text.

    routing_table format:
      routing_table[node_id] = {
          "paths": [ [node,...,'sink'], ... ],   # each path starts at node and ends at 'sink'
          "P": int or None
      }

    Note: sensor_nodes is a dict node_id -> SensorNode
          G is a networkx Graph with positions and edges already added
          sink_node.node_id should be the object's node id (e.g., 'sink')
    """

    sink_id = sink_node.node_id
    sink_pos = sink_node.location

    # 1) compute distances d_vs for all sensor nodes
    node_distances = {}
    for nid, node in sensor_nodes.items():
        node_distances[nid] = math.dist(node.location, sink_pos)

    # 2) average distance averds (over sensor nodes reachable in initial D0)
    #    In your description, averds is "average distance between sink and nodes within D0".
    #    We don't have D0 here; use average over all sensor nodes as an approximation.
    if len(node_distances) > 0:
        avg_ds = sum(node_distances.values()) / len(node_distances)
    else:
        avg_ds = 1.0

    # helper f(n, d) = n + ceil(d/avg_ds)
    def f(n, d):
        return int(n + math.ceil(d / (avg_ds if avg_ds > 0 else 1.0)))

    # Initialize routing table dictionary
    routing_table = {}

    # Sink's own entry: define its path list as [[sink]] and P = 0
    routing_table[sink_id] = {"paths": [[sink_id]], "P": 0}
    sink_node.P = 0
    sink_node.routing_paths = []

    # Queue of (sender, receiver) broadcast updates to process.
    # Start by enqueuing broadcasts from sink to its neighbors.
    queue = deque()
    for nbr in G.neighbors(sink_id):
        if nbr in sensor_nodes:
            # Tu for sink is [[sink]], so Tv for neighbor will be [ [nbr, sink] ]
            # We'll prepare an entry for neighbor in the routing table (if missing)
            if nbr not in routing_table:
                routing_table[nbr] = {"paths": [], "P": None}
            # create initial Tv from Tu by appending IDv to each path in Tu
            new_paths = []
            for path in routing_table[sink_id]["paths"]:
                # path is ['sink'] -> neighbor path is [neighbor, 'sink']
                new_paths.append([nbr] + list(path))
            # store them (may be overwritten/merged later)
            routing_table[nbr]["paths"].extend(new_paths)
            queue.append((sink_id, nbr))

    # Process queue: simulate nodes forwarding updates to their neighbors
    while queue:
        sender, receiver = queue.popleft()
        # sender's routing table Tu
        Tu = routing_table.get(sender, {"paths": [], "P": None})["paths"]

        # receiver node object
        if receiver not in sensor_nodes:
            # receiver might be sink or an unknown node; skip if not sensor
            continue
        v_node = sensor_nodes[receiver]

        changed = False

        # If receiver has no P assigned yet -> initialize based on Tu
        if routing_table.get(receiver, {"P": None})["P"] is None:
            # store PPK would happen here in real system (we already have it globally)
            # compute d_vs
            d_vs = node_distances.get(receiver, math.dist(v_node.location, sink_pos))
            # n = max number of hops among paths in Tu (if Tu empty, n=0)
            if len(Tu) == 0:
                n = 0
            else:
                # each path stores nodes starting at sender and ending at sink
                n = max((len(p) - 1) for p in Tu)  # hops = nodes_in_path - 1

            # compute P using f(n, d_vs) (following your description)
            P_v = f(n, d_vs)
            routing_table[receiver] = {"paths": [], "P": P_v}
            v_node.P = P_v

            # append IDv to each path in Tu and save as Tv
            Tv = []
            for path in Tu:
                # prepend receiver to the path
                new_path = [receiver] + list(path)
                # ensure no duplicates
                if new_path not in Tv:
                    Tv.append(new_path)
            routing_table[receiver]["paths"].extend(Tv)
            v_node.routing_paths = routing_table[receiver]["paths"].copy()
            changed = True

        else:
            # Receiver already has P. According to algorithm:
            # "There is a set of paths in Tu that do not belong to Tv and whose routing hops are less than P,
            #  append IDv to each path in the set and update Tv"
            P_v = routing_table[receiver]["P"]
            # select candidate paths from Tu whose hops <= P_v - 1 (since after adding receiver they become <= P_v)
            candidates = []
            for path in Tu:
                hops_in_path = len(path) - 1  # hops in Tu's paths (sender->...->sink)
                if hops_in_path <= (P_v - 1):
                    # candidate path for receiver is [receiver] + path
                    new_path = [receiver] + list(path)
                    # add only if not already present
                    if new_path not in routing_table[receiver]["paths"]:
                        candidates.append(new_path)
            if candidates:
                routing_table[receiver]["paths"].extend(candidates)
                v_node.routing_paths = routing_table[receiver]["paths"].copy()
                changed = True

        # If changed or first-time receive (above), forward update to neighbors except sender
        if changed:
            for nbr in G.neighbors(receiver):
                if nbr == sender:
                    continue
                # only forward to graph neighbors that are sensor nodes (skip sink here if needed)
                if nbr in sensor_nodes:
                    # Ensure the sender entry exists for the neighbor's processing
                    if nbr not in routing_table:
                        routing_table[nbr] = {"paths": [], "P": None}
                    # When sending, neighbor will receive Tu = routing_table[receiver]["paths"]
                    # so enqueue (receiver -> nbr)
                    queue.append((receiver, nbr))

    # After propagation completes, assign routing paths and P to all sensor nodes
    for nid, node in sensor_nodes.items():
        entry = routing_table.get(nid)
        if entry:
            node.routing_paths = entry["paths"].copy()
            node.P = entry["P"]
        else:
            node.routing_paths = []
            node.P = None

    # Debug print (concise)
    print("\n--- Routing Table Summary ---")
    for nid in sorted(sensor_nodes.keys(), key=lambda x: (isinstance(x, str), x)):
        node = sensor_nodes[nid]
        print(f"Node {nid}: P={node.P}, paths={node.routing_paths}")

    return routing_table
