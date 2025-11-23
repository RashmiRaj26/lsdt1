import math
import random
from collections import deque
import matplotlib.pyplot as plt

# ------------------------
# Sink Node & Sensor Node Classes
# ------------------------
class SinkNode:
    def __init__(self, area_size, D0):
        self.xs = random.uniform(0, area_size)
        self.ys = random.uniform(0, area_size)
        self.D0 = D0
        self.pk, self.sk = self.AE_Setup(128)  # dummy keys
        self.lambda_coeff = 0.5
        self.hash_function = "H(x)"
        self.calc_function = "f(P)"
        self.Gq = "Gq"
        self.g = "g"
        self.PPK = {"Location": (self.xs, self.ys),
                    "PublicKey": self.pk,
                    "f": self.calc_function,
                    "λ": self.lambda_coeff,
                    "H": self.hash_function,
                    "Gq": self.Gq,
                    "g": self.g}
        self.SM = {"PPK": self.PPK, "hop": 0, "R": []}

    def AE_Setup(self, security_param):
        # Dummy asymmetric encryption setup
        pk = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=8))
        sk = ''.join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", k=8))
        return pk, sk

class SensorNode:
    def __init__(self, node_id, area_size, E0, theta, D_min=15, D_max=35):
        self.node_id = node_id
        self.x = random.uniform(0, area_size)
        self.y = random.uniform(0, area_size)
        self.energy = random.uniform(E0, (1 + theta) * E0)
        self.comm_radius = random.uniform(D_min, D_max)
        self.neighbors = []
        self.PPK = None
        self.Tu = []       # initial routing paths
        self.Tv = []       # final multi-path routing table
        self.P = None      # maximum hop count
        self.dus = None    # distance to sink

    def __repr__(self):
        return f"Node {self.node_id} (P={self.P})"

# ------------------------
# Sensor Network Class
# ------------------------
class SensorNetwork:
    def __init__(self, num_nodes, area_size, E0, theta, D0):
        self.num_nodes = num_nodes
        self.area_size = area_size
        self.E0 = E0
        self.theta = theta
        self.sink = SinkNode(area_size, D0)
        self.nodes = [SensorNode(i, area_size, E0, theta) for i in range(1, num_nodes + 1)]
        self.calculate_neighbors()

    def calculate_neighbors(self):
        for i in range(len(self.nodes)):
            for j in range(i + 1, len(self.nodes)):
                n1, n2 = self.nodes[i], self.nodes[j]
                dist = math.dist((n1.x, n1.y), (n2.x, n2.y))
                if dist < min(n1.comm_radius, n2.comm_radius):
                    n1.neighbors.append(n2.node_id)
                    n2.neighbors.append(n1.node_id)

    def distance_to_sink(self, node):
        return math.dist((node.x, node.y), (self.sink.xs, self.sink.ys))

    def get_node_by_id(self, node_id):
        return next(n for n in self.nodes if n.node_id == node_id)

# ------------------------
# Step 1: Initial Maximum P-Hop Route Construction
# ------------------------
def step1_maxP_routes(network, P):
    queue = deque()
    for node in network.nodes:
        dist_to_sink = network.distance_to_sink(node)
        if dist_to_sink <= network.sink.D0:
            node.PPK = network.sink.PPK
            path = [node.node_id, 's']
            node.Tu.append(path)
            queue.append((node, path, 1))

    while queue:
        current_node, current_path, hop = queue.popleft()
        if hop >= P:
            continue
        for neighbor_id in current_node.neighbors:
            neighbor = network.get_node_by_id(neighbor_id)
            if network.distance_to_sink(neighbor) > network.distance_to_sink(current_node):
                new_path = current_path + [neighbor.node_id]
                if new_path not in neighbor.Tu:
                    neighbor.Tu.append(new_path)
                    queue.append((neighbor, new_path, hop + 1))

# ------------------------
# Step 2: Calculate Maximum Hop Count P for Each Node
# ------------------------
def step2_calculate_P(network):
    nodes_within_D0 = [node for node in network.nodes if network.distance_to_sink(node) <= network.sink.D0]
    averds = sum(network.distance_to_sink(node) for node in nodes_within_D0) / len(nodes_within_D0) if nodes_within_D0 else 1
    network.sink.PPK['averds'] = averds

    for node in network.nodes:
        if node.Tu:
            n = max(len(path) for path in node.Tu)
            dus = network.distance_to_sink(node)
            node.dus = dus
            node.P = n + math.ceil(dus / averds)
        else:
            node.P = None

# ------------------------
# Step 3: Multi-Hop Routing Propagation (Algorithm 1)
# ------------------------
def step3_routing_propagation(network):
    queue = deque()
    for node in network.nodes:
        if node.P is not None and network.distance_to_sink(node) <= network.sink.D0:
            node.Tv = [path[:] for path in node.Tu]
            queue.append((node, None))

    while queue:
        current_node, sender = queue.popleft()
        for neighbor_id in current_node.neighbors:
            if sender is not None and neighbor_id == sender.node_id:
                continue
            neighbor = network.get_node_by_id(neighbor_id)
            change = False

            # Only propagate to nodes farther from sink
            if network.distance_to_sink(neighbor) > network.distance_to_sink(current_node):
                if neighbor.P is None:
                    neighbor.PPK = network.sink.PPK
                    neighbor.dus = network.distance_to_sink(neighbor)
                    n = max(len(path) for path in current_node.Tv) if current_node.Tv else 0
                    neighbor.P = n + math.ceil(neighbor.dus / network.sink.PPK['averds'])
                    neighbor.Tv = [path + [neighbor.node_id] for path in current_node.Tv]
                    change = True
                else:
                    for path in current_node.Tv:
                        new_path = path + [neighbor.node_id]
                        if new_path not in neighbor.Tv and len(new_path) <= neighbor.P:
                            neighbor.Tv.append(new_path)
                            change = True

            if change:
                queue.append((neighbor, current_node))

# ------------------------
# Step 4: Display Routing Paths with Explanations
# ------------------------
def display_routing_paths_verbose(network):
    print("\n=== Routing Paths and Explanations for Each Node ===\n")
    for node in network.nodes:
        print(f"Node {node.node_id} (Maximum hops P={node.P}):")
        if node.Tv:
            for idx, path in enumerate(node.Tv, start=1):
                path_str = " -> ".join(map(str, path))
                explanation = f"Path {idx}: Data from Node {node.node_id} will traverse nodes in order: {path_str} to reach the Sink 's'."
                print("  " + explanation)
        else:
            print(f"  Node {node.node_id} has no available paths to the sink yet.")
        print()

# ------------------------
# Step 5: Visualize Network & Routing Paths
# ------------------------
def visualize_network(network):
    plt.figure(figsize=(8, 8))
    # Plot sink
    plt.scatter(network.sink.xs, network.sink.ys, c='red', s=200, label='Sink Node')
    plt.text(network.sink.xs+1, network.sink.ys+1, 'Sink', color='red')

    # Plot sensor nodes
    for node in network.nodes:
        plt.scatter(node.x, node.y, c='blue', s=100)
        plt.text(node.x+1, node.y+1, f'{node.node_id}', color='blue', fontsize=9)

    # Plot routing paths
    for node in network.nodes:
        if node.Tv:
            for path in node.Tv:
                for i in range(len(path)-1):
                    n1 = network.get_node_by_id(path[i]) if path[i] != 's' else network.sink
                    n2 = network.get_node_by_id(path[i+1]) if path[i+1] != 's' else network.sink
                    plt.plot([n1.x if path[i] != 's' else n1.xs, n2.x if path[i+1] != 's' else n2.xs],
                             [n1.y if path[i] != 's' else n1.ys, n2.y if path[i+1] != 's' else n2.ys],
                             c='green', alpha=0.3)

    plt.title("Sensor Network with Routing Paths")
    plt.xlim(0, network.area_size)
    plt.ylim(0, network.area_size)
    plt.legend()
    plt.grid(True)
    plt.show()

# ------------------------
# Main Simulation
# ------------------------
def main():
    N = 50        # Number of sensor nodes
    W = 100       # Area size
    E0 = 50       # Basic energy unit
    theta = 0.5   # Heterogeneity coefficient
    D0 = 50       # Increased sink initial broadcast range for proper path initialization
    P_initial = 3 # Initial P-hop limit for Step 1

    network = SensorNetwork(N, W, E0, theta, D0)

    # Step 1: Initial routes from sink
    step1_maxP_routes(network, P_initial)
    # Step 2: Compute maximum hop counts
    step2_calculate_P(network)
    # Step 3: Multi-hop routing propagation
    step3_routing_propagation(network)
    # Step 4: Display routing tables with explanations
    display_routing_paths_verbose(network)
    # Step 5: Visualize network and paths
    visualize_network(network)

if __name__ == "__main__":
    main()
