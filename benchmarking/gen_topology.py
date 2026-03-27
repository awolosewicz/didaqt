#!/usr/bin/env python3
"""Generate a DiDAQt benchmark topology YAML.

Usage: gen_topology.py <target_paths> <switch_count> [output_file]

Generates a fat-tree-like topology where:
  - First-layer switches have 36 ports (24 sender input, 12 output)
  - Other switches have 24 ports
  - Senders are grouped in 4s to a single receiver (25G each, 100G receiver)
  - Switch-to-switch: 6 ports to child-A, 6 to child-B
  - Last-layer switches connect to 12 receivers each
  - Twice as many receivers as required (6 used + 6 spare per last-layer switch)

The target_paths parameter is the approximate receiver count (topology scale).
Rounded up to a multiple of 12 * 2^(switch_count-1) for valid layer sizes.
"""

import sys
import math


def round_up(n, m):
    return ((n + m - 1) // m) * m


def gen_topology(target_paths, switch_count):
    granularity = 12 * (1 << (switch_count - 1))
    n_recv = round_up(target_paths, granularity)

    n_last = n_recv // 12
    n_first = n_last // (1 << (switch_count - 1))
    if n_first < 1:
        n_first = 1
        n_recv = granularity

    n_senders = n_first * 24
    n_receivers = n_recv

    # Layer counts (0-indexed layers, layer 0 = first)
    layer_counts = []
    for l in range(switch_count):
        layer_counts.append(n_first * (1 << l))

    lines = []

    # ---- Senders ----
    for s in range(1, n_senders + 1):
        sw_idx = (s - 1) // 24           # 0-indexed first-layer switch
        j = (s - 1) % 24                 # position within switch (0-23)
        group = ((s - 1) // 4) + 1       # 1-indexed group
        g = j // 4                        # group within switch (0-5)

        # Primary last-layer switch through child-A at every hop
        primary_last = sw_idx * (1 << (switch_count - 1))
        initial_recv = primary_last * 12 + g + 1

        sw_name = f"SW1_{sw_idx + 1}"

        lines.append(f"- name: S{s}")
        lines.append(f"  type: sender")
        lines.append(f"  sender_id: {s}")
        lines.append(f"  sender_id_bytes: 1")
        lines.append(f"  max_bandwidth: 25G")
        lines.append(f"  initial_receiver: R{initial_recv}")
        lines.append(f"  group_id: {group}")
        lines.append(f"  connections:")
        lines.append(f"    1:")
        lines.append(f"      other_node: {sw_name}")
        lines.append(f"      other_port: {j + 1}")
        lines.append(f"      max_bandwidth: 100G")
        lines.append("")

    # ---- Switches ----
    for layer in range(switch_count):
        n_sw = layer_counts[layer]
        is_first = (layer == 0)
        is_last = (layer == switch_count - 1)

        for i in range(n_sw):
            sw_name = f"SW{layer + 1}_{i + 1}"
            lines.append(f"- name: {sw_name}")
            lines.append(f"  type: switch")
            lines.append(f"  switch_type_group: tofino2")
            lines.append(f"  connections:")

            if is_first:
                # Sender input ports (1-24)
                for j in range(24):
                    sid = i * 24 + j + 1
                    lines.append(f"    {j + 1}:")
                    lines.append(f"      other_node: S{sid}")
                    lines.append(f"      other_port: 1")
                    lines.append(f"      max_bandwidth: 100G")

            if not is_first:
                # Input from parent (ports 1-6)
                parent_idx = i // 2
                parent_layer = layer - 1
                parent_name = f"SW{parent_layer + 1}_{parent_idx + 1}"
                child_slot = i % 2  # 0 = child-A, 1 = child-B
                if parent_layer == 0:
                    parent_base = 25 + child_slot * 6
                else:
                    parent_base = 7 + child_slot * 6
                for j in range(6):
                    lines.append(f"    {j + 1}:")
                    lines.append(f"      other_node: {parent_name}")
                    lines.append(f"      other_port: {parent_base + j}")
                    lines.append(f"      max_bandwidth: 100G")

            if is_first and is_last:
                # 1-switch case: receiver output ports (25-36)
                for j in range(12):
                    rid = i * 12 + j + 1
                    lines.append(f"    {25 + j}:")
                    lines.append(f"      other_node: R{rid}")
                    lines.append(f"      other_port: 1")
                    lines.append(f"      max_bandwidth: 100G")

            elif is_first and not is_last:
                # First layer, multi-switch: output to children (ports 25-36)
                child_a = i * 2
                child_b = i * 2 + 1
                child_a_name = f"SW{layer + 2}_{child_a + 1}"
                child_b_name = f"SW{layer + 2}_{child_b + 1}"
                for j in range(6):
                    lines.append(f"    {25 + j}:")
                    lines.append(f"      other_node: {child_a_name}")
                    lines.append(f"      other_port: {j + 1}")
                    lines.append(f"      max_bandwidth: 100G")
                for j in range(6):
                    lines.append(f"    {31 + j}:")
                    lines.append(f"      other_node: {child_b_name}")
                    lines.append(f"      other_port: {j + 1}")
                    lines.append(f"      max_bandwidth: 100G")

            elif is_last and not is_first:
                # Last layer: receiver output ports (7-18)
                for j in range(12):
                    rid = i * 12 + j + 1
                    lines.append(f"    {7 + j}:")
                    lines.append(f"      other_node: R{rid}")
                    lines.append(f"      other_port: 1")
                    lines.append(f"      max_bandwidth: 100G")

            elif not is_first and not is_last:
                # Middle layer: output to children (ports 7-18)
                child_a = i * 2
                child_b = i * 2 + 1
                child_a_name = f"SW{layer + 2}_{child_a + 1}"
                child_b_name = f"SW{layer + 2}_{child_b + 1}"
                for j in range(6):
                    lines.append(f"    {7 + j}:")
                    lines.append(f"      other_node: {child_a_name}")
                    lines.append(f"      other_port: {j + 1}")
                    lines.append(f"      max_bandwidth: 100G")
                for j in range(6):
                    lines.append(f"    {13 + j}:")
                    lines.append(f"      other_node: {child_b_name}")
                    lines.append(f"      other_port: {j + 1}")
                    lines.append(f"      max_bandwidth: 100G")

            lines.append("")

    # ---- Receivers ----
    for r in range(1, n_receivers + 1):
        last_sw_idx = (r - 1) // 12      # 0-indexed last-layer switch
        port_in_sw = (r - 1) % 12        # 0-indexed port position
        last_layer = switch_count
        last_sw_name = f"SW{last_layer}_{last_sw_idx + 1}"
        if switch_count == 1:
            sw_port = 25 + port_in_sw
        else:
            sw_port = 7 + port_in_sw

        lines.append(f"- name: R{r}")
        lines.append(f"  type: receiver")
        lines.append(f"  receiver_id: {r}")
        lines.append(f"  connections:")
        lines.append(f"    1:")
        lines.append(f"      other_node: {last_sw_name}")
        lines.append(f"      other_port: {sw_port}")
        lines.append(f"      max_bandwidth: 100G")
        lines.append("")

    # Summary comment at top
    total_switches = sum(layer_counts)
    header = [
        f"# Benchmark topology: {n_senders} senders, {total_switches} switches "
        f"({switch_count} layers), {n_receivers} receivers",
        f"# Target: {target_paths}, rounded: {n_recv}",
        f"# Paths per sender: {12 * (1 << (switch_count - 1))}",
        f"# Total DFS paths: {n_senders * 12 * (1 << (switch_count - 1))}",
        "",
    ]

    return "\n".join(header + lines)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_paths> <switch_count> [output_file]",
              file=sys.stderr)
        sys.exit(1)

    target = int(sys.argv[1])
    sc = int(sys.argv[2])
    yaml_text = gen_topology(target, sc)

    if len(sys.argv) >= 4:
        with open(sys.argv[3], "w") as f:
            f.write(yaml_text)
    else:
        print(yaml_text)
