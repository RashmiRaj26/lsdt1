import time
import matplotlib.pyplot as plt
from msgtrans import transmit_message, Message, receive_message_override

# Define the SensorNode class inline for simplicity
class SensorNode:
    def __init__(self, node_id, energy, location, transmission_radius, is_sink=False):
        self.node_id = node_id
        self.energy = energy
        self.location = location
        self.transmission_radius = transmission_radius
        self.is_sink = is_sink
        self.neighbors = []
        self.reputation = 1.0
        self.detected_as_malicious = False
        self.messages_forwarded = {}

    def distance_to(self, other):
        x1, y1 = self.location
        x2, y2 = other.location
        return ((x1 - x2) ** 2 + (y1 - y2) ** 2) ** 0.5

    def can_communicate_with(self, other):
        return self.distance_to(other) <= self.transmission_radius

    def add_neighbor(self, other):
        if self.can_communicate_with(other):
            self.neighbors.append(other)

# Bind the message receiving behavior
SensorNode.receive_message = receive_message_override

# Create nodes for simulation
sink = SensorNode(0, 1000, (100, 100), 150, is_sink=True)
s1 = SensorNode(1, 100, (10, 10), 80)
s2 = SensorNode(2, 90, (35, 35), 80)
s3 = SensorNode(3, 85, (60, 60), 80)
s4 = SensorNode(4, 95, (85, 85), 80)

nodes = [sink, s1, s2, s3, s4]

# Set up neighbors
for node in nodes:
    for other in nodes:
        if node != other:
            node.add_neighbor(other)

# Show initial setup
print("\n✅ Initial Node Setup:")
for node in nodes:
    print(f"Node {node.node_id} at {node.location} with energy {node.energy}")
    print(f"  Neighbors: {[n.node_id for n in node.neighbors]}")
    time.sleep(0.5)

# Create a message from source to sink
msg = Message(
    msg_id=101,
    share="s101",
    timestamp="T1",
    path=[1, 2, 3, 4, 0],  # Suggested reference path
    path_star=[1]          # Source node already visited
)

# Visualization helper
plt.ion()
fig, ax = plt.subplots(figsize=(8, 8))

def draw_network(path_star):
    ax.clear()
    for node in nodes:
        x, y = node.location
        color = 'blue' if node.is_sink else 'green'
        if node.node_id in path_star:
            color = 'red'
        ax.scatter(x, y, c=color, s=200)
        ax.text(x + 2, y + 2, f"{node.node_id}", fontsize=10)
        for neighbor in node.neighbors:
            nx, ny = neighbor.location
            ax.plot([x, nx], [y, ny], 'gray', linestyle='dotted', linewidth=0.5)

    for i in range(len(path_star) - 1):
        n1 = next(n for n in nodes if n.node_id == path_star[i])
        n2 = next(n for n in nodes if n.node_id == path_star[i+1])
        ax.plot([n1.location[0], n2.location[0]], [n1.location[1], n2.location[1]], 'red', linewidth=2)

    ax.set_title("Message Transmission Visualization")
    ax.set_xlim(0, 120)
    ax.set_ylim(0, 120)
    ax.grid(True)
    plt.pause(1)

print("\n🚀 Starting Message Transmission Simulation:\n")

# Monkey patch the transmit_message to update visualization after each hop
original_transmit_message = transmit_message

def visual_transmit(source_node, message, sink_node, lambda_weight=2, message_bit_length=512):
    draw_network(message.path_star)
    original_transmit_message(source_node, message, sink_node, lambda_weight, message_bit_length)

# Replace the transmit_message with visual one
import msgtrans
msgtrans.transmit_message = visual_transmit

# Begin transmission
visual_transmit(s1, msg, sink)

print("\n✅ Final Path Traversed:")
print(" -> ".join(str(nid) for nid in msg.path_star))

plt.ioff()
plt.show()