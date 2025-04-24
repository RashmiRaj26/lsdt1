import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time

def simulate(path, sink, all_nodes, delay=1.0):
    fig, ax = plt.subplots()
    ax.set_title("HWSN Message Transmission Visualization")
    ax.set_xlim(0, 120)
    ax.set_ylim(0, 120)

    # Plot all nodes
    for node_id, node in all_nodes.items():
        ax.plot(node.location[0], node.location[1], 'bo')
        ax.text(node.location[0] + 1, node.location[1] + 1, node_id, fontsize=9)

    # Plot the sink
    ax.plot(sink.location[0], sink.location[1], 'ro')
    ax.text(sink.location[0] + 1, sink.location[1] + 1, 'Sink', fontsize=9, color='red')

    # Step-by-step transmission animation
    for i in range(len(path) - 1):
        node_a = all_nodes[path[i]] if path[i] != 'sink' else sink
        node_b = all_nodes[path[i + 1]] if path[i + 1] != 'sink' else sink

        # Plot the link line
        ax.plot([node_a.location[0], node_b.location[0]],
                [node_a.location[1], node_b.location[1]], 'g--', linewidth=2)

        # Highlight the transmitting node
        ax.plot(node_a.location[0], node_a.location[1], 'go', markersize=10)

        plt.draw()  # Force redraw of the plot after each update
        plt.pause(delay)  # Delay to simulate the message transmission

    # After loop: Make sure to plot the last line to the sink node
    # Only plot the line to the sink if the sink is actually reached
    if path[-1] == 'sink':
        second_last = all_nodes[path[-2]]
        ax.plot([second_last.location[0], sink.location[0]],
            [second_last.location[1], sink.location[1]], 'g--', linewidth=2)

    # Highlight the sink node again to show final reception
    ax.plot(sink.location[0], sink.location[1], 'ro', markersize=12)

    plt.draw()  # Redraw the final state
    plt.show()  # Show the final plot with the complete path

