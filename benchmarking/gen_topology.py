#!/usr/bin/env python3
"""Generate a DiDAQt benchmark topology YAML.

Usage: gen_topology.py <target_senders> <switch_count> [output_file]

Generates a butterfly-style topology where:
  - Path number = number of senders
  - Receivers = senders / 2 (4 senders per receiver, 2x redundancy)
  - M = senders / 24 switch columns, identical at every stage
  - Stage 0: 24 sender inputs + 2 outputs (straight + cross)
  - Intermediate stages: 2 inputs + 2 outputs (straight + cross)
  - Last stage: 2 inputs + 12 receiver outputs
  - Cross pattern: stage s→s+1, switch i cross-connects to i XOR 2^s

Paths per sender = 2^(switch_count-1) * 12.
M is rounded so it's a multiple of 4 (supports butterfly masks 1,2).
"""

import sys
import math


def round_up(n, m):
    return ((n + m - 1) // m) * m


def gen_topology(target_senders, switch_count):
    # M must be a multiple of 2^(switch_count-1) for the butterfly XOR
    # masks.  Use multiple of 4 so the same M works for sc=1,2,3.
    M = round_up(math.ceil(target_senders / 24), 4)
    if M < 4:
        M = 4

    n_senders = M * 24
    n_receivers = M * 12
    num_stages = switch_count

    lines = []

    # ---- Senders ----
    for s in range(1, n_senders + 1):
        col = (s - 1) // 24                # 0-indexed switch column
        j = (s - 1) % 24                   # position within switch (0-23)
        group = ((s - 1) // 4) + 1         # 1-indexed group
        g = j // 4                          # group within switch (0-5)

        # Initial receiver: straight path through every stage → same column
        initial_recv = col * 12 + g + 1

        sw_name = f"SW0_{col + 1}"

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
    for stage in range(num_stages):
        is_first = (stage == 0)
        is_last = (stage == num_stages - 1)

        for i in range(M):
            sw_name = f"SW{stage}_{i + 1}"
            lines.append(f"- name: {sw_name}")
            lines.append(f"  type: switch")
            lines.append(f"  switch_type_group: tofino2")
            lines.append(f"  connections:")

            next_port = 1  # next available port number

            # --- Sender inputs (stage 0 only) ---
            if is_first:
                for j in range(24):
                    sid = i * 24 + j + 1
                    lines.append(f"    {next_port}:")
                    lines.append(f"      other_node: S{sid}")
                    lines.append(f"      other_port: 1")
                    lines.append(f"      max_bandwidth: 100G")
                    next_port += 1

            # No backward connections for non-first stages.
            # The DFS enters via arrived_port (which it skips), so
            # no connection definition is needed on the input ports.
            # This prevents the DFS from zigzagging backwards through
            # the butterfly, which would cause path explosion.
            if not is_first:
                # Reserve port numbers for the inputs (used as arrived_port)
                next_port = 3  # ports 1,2 are inputs (straight, cross)

            # --- Outputs ---
            if is_first and is_last:
                # switch_count=1: direct to 12 receivers
                for j in range(12):
                    rid = i * 12 + j + 1
                    lines.append(f"    {next_port}:")
                    lines.append(f"      other_node: R{rid}")
                    lines.append(f"      other_port: 1")
                    lines.append(f"      max_bandwidth: 100G")
                    next_port += 1

            elif is_last and not is_first:
                # Last stage (sc>1): 12 receiver outputs
                for j in range(12):
                    rid = i * 12 + j + 1
                    lines.append(f"    {next_port}:")
                    lines.append(f"      other_node: R{rid}")
                    lines.append(f"      other_port: 1")
                    lines.append(f"      max_bandwidth: 100G")
                    next_port += 1

            else:
                # First or intermediate: 2 outputs (straight + cross)
                next_stage = stage + 1
                mask = 1 << stage  # butterfly mask for this→next transition

                # Straight output → next stage, same column
                straight_dst = i
                next_sw = f"SW{next_stage}_{straight_dst + 1}"
                lines.append(f"    {next_port}:")
                lines.append(f"      other_node: {next_sw}")
                lines.append(f"      other_port: 1")  # input port 1 on next switch
                lines.append(f"      max_bandwidth: 600G")
                straight_port = next_port
                next_port += 1

                # Cross output → next stage, column i XOR mask
                cross_dst = i ^ mask
                next_sw_cross = f"SW{next_stage}_{cross_dst + 1}"
                lines.append(f"    {next_port}:")
                lines.append(f"      other_node: {next_sw_cross}")
                lines.append(f"      other_port: 2")  # input port 2 on next switch
                lines.append(f"      max_bandwidth: 600G")
                next_port += 1

            lines.append("")

    # ---- Receivers ----
    last_stage = num_stages - 1
    for r in range(1, n_receivers + 1):
        col = (r - 1) // 12
        port_in_sw = (r - 1) % 12
        last_sw = f"SW{last_stage}_{col + 1}"
        # Receiver port on the last-stage switch
        if num_stages == 1:
            sw_port = 25 + port_in_sw   # stage 0 only: after 24 sender ports
        else:
            sw_port = 3 + port_in_sw    # after 2 input ports

        lines.append(f"- name: R{r}")
        lines.append(f"  type: receiver")
        lines.append(f"  receiver_id: {r}")
        lines.append(f"  connections:")
        lines.append(f"    1:")
        lines.append(f"      other_node: {last_sw}")
        lines.append(f"      other_port: {sw_port}")
        lines.append(f"      max_bandwidth: 100G")
        lines.append("")

    # Summary
    paths_per_sender = 12 * (1 << (switch_count - 1))
    total_paths = n_senders * paths_per_sender
    header = [
        f"# Butterfly topology: {n_senders} senders, "
        f"{M * num_stages} switches ({num_stages} stages x {M} columns), "
        f"{n_receivers} receivers",
        f"# Target senders: {target_senders}, rounded: {n_senders}",
        f"# Paths per sender: {paths_per_sender}",
        f"# Total DFS paths: {total_paths}",
        "",
    ]

    return "\n".join(header + lines)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <target_senders> <switch_count> [output_file]",
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
