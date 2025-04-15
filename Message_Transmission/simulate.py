from msgtrans import transmit_message, Message
import matplotlib.pyplot as plt
import time

# SensorNode class (inline version)
class SensorNode:
    def __init__(self, node_id, energy, location, transmission_radius, is_sink=False):
        self.node_id = node_id
        self.energy = energy
        self.location = location
        self.transmission_radius = transmission_radius
        self.is_sink = is_sink
        self.neighbors = []
        self.routing_table = []
        self.reputation = 1.0
        self.suspicion_score = 1
        self.messages_forwarded = {}
        self.detected_as_malicious = False

    def distance_to(self, other_node):
        x1, y1 = self.location
        x2, y2 = other_node.location
        return ((x2 - x1)**2 + (y2 - y1)**2)**0.5

    def can_communicate_with(self, other_node):
        return self.distance_to(other_node) <= self.transmission_radius

    def add_neighbor(self, other_node):
        if self.can_communicate_with(other_node):
            self.neighbors.append(other_node)

    def update_reputation(self, delta):
        self.suspicion_score += delta
        self.reputation = 1 / self.suspicion_score

    def mark_as_malicious(self):
        self.detected_as_malicious = True
        self.reputation = 0.0

    def receive_message(self, message, sender):
        print(f"Node {self.node_id} received message {message.id} from Node {sender.node_id}")
        self.messages_forwarded[message.id] = message

    def __repr__(self):
        return f"SensorNode(id={self.node_id}, energy={self.energy:.2f}, rep={self.reputation:.2f})"

# Step 1: Create the nodes
sink = SensorNode(node_id=0, energy=999, location=(100, 100), transmission_radius=120, is_sink=True)
node1 = SensorNode(node_id=1, energy=100, location=(10, 10), transmission_radius=80)
node2 = SensorNode(node_id=2, energy=90, location=(40, 40), transmission_radius=80)
node3 = SensorNode(node_id=3, energy=85, location=(70, 70), transmission_radius=80)
node4 = SensorNode(node_id=4, energy=95, location=(90, 90), transmission_radius=80)

nodes = [sink, node1, node2, node3, node4]

# Step 2: Establish neighbors based on communication radius
for node in nodes:
    for other in nodes:
        if node != other and node.can_communicate_with(other):
            node.add_neighbor(other)

# Step 3: Print initial state
print("\n✅ Initial Network State:")
for node in nodes:
    print(node)
    print(f"  Neighbors: {[n.node_id for n in node.neighbors]}")

# Step 4: Create a message to send from source (node1) to sink
msg = Message(
    msg_id=101,
    share="s101",
    timestamp="T1",
    path=[1, 2, 3, 4, 0],
    path_star=[1]  # Already visited by source
)

# Step 5: Start transmission
print("\n🚀 Starting Message Transmission...\n")
try:
    transmit_message(source_node=node1, message=msg, sink_node=sink)
except ZeroDivisionError:
    print("[X] Error: Division by zero occurred during IF calculation. Check if node is too close to the sink (distance = 0).")

# Step 6: Final network state
print("\n✅ Final State After Transmission:")
for node in nodes:
    print(node)
    print(f"  Energy Left: {node.energy:.2f}")
    print(f"  Messages Forwarded: {list(node.messages_forwarded.keys())}\n")

# Step 7: Print Message Transmission Path
print("🚚 Message Transmission Path:")
print(" -> ".join(map(str, msg.path_star)))

# Step 8: Animated Visual of the Transmission Path
plt.ion()
fig, ax = plt.subplots(figsize=(8, 8))
for i in range(len(msg.path_star)):
    ax.clear()
    ax.set_title("Animated HWSN Message Transmission")
    ax.set_xlim(0, 120)
    ax.set_ylim(0, 120)
    ax.set_xlabel("X Position")
    ax.set_ylabel("Y Position")
    ax.grid(True)

    for node in nodes:
        x, y = node.location
        color = 'blue' if node.is_sink else ('red' if node.node_id == msg.path_star[i] else 'green')
        ax.scatter(x, y, c=color, s=300)
        ax.text(x + 1, y + 1, f"{node.node_id}", fontsize=10)
        for neighbor in node.neighbors:
            nx, ny = neighbor.location
            ax.plot([x, nx], [y, ny], 'gray', linestyle='dotted', linewidth=1)

    for j in range(i):
        n1 = next(n for n in nodes if n.node_id == msg.path_star[j])
        n2 = next(n for n in nodes if n.node_id == msg.path_star[j + 1])
        x1, y1 = n1.location
        x2, y2 = n2.location
        ax.plot([x1, x2], [y1, y2], 'orange', linewidth=3)

    plt.pause(1)

plt.ioff()
plt.show()