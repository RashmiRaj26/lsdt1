# nodes.py

class SensorNode:
    def __init__(self, node_id, location, initial_energy, communication_radius):
        self.node_id = node_id
        self.location = location
        self.initial_energy = initial_energy
        self.communication_radius = communication_radius
        self.routing_paths = []

    def __repr__(self):
        return (f"SensorNode(id={self.node_id}, location={self.location}, "
                f"initial_energy={self.initial_energy}, "
                f"communication_radius={self.communication_radius})")

class SinkNode:
    def __init__(self, location):
        self.node_id = None
        self.location = location
        self.public_key = None
        self.private_key = None
        self.weighting_coefficient = 0.5
        self.hash_function = None
        self.max_hops = 5

    def __repr__(self):
        return (f"SinkNode(location={self.location}, "
                f"weighting_coefficient={self.weighting_coefficient}, "
                f"max_hops={self.max_hops})")
