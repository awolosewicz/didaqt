#!/usr/bin/env python3
"""Generate a simple star topology for the DiDAQt overhead benchmark.

Usage: gen_overhead_topology.py <num_receivers> <senders_per_receiver> <output_file>

Generates M independent groups, each:
  S senders -> 1 switch -> 1 receiver

Receiver r has senders (r-1)*S+1 through r*S.
Each sender has its own group (group_id = sender_id).
"""

import sys


def gen_overhead_topology(num_receivers, senders_per_recv, out):
    n_senders = num_receivers * senders_per_recv
    n_switches = num_receivers

    out.write(f"# Star topology: {n_senders} senders, "
              f"{n_switches} switches, {num_receivers} receivers\n")
    out.write(f"# {senders_per_recv} senders per receiver, "
              f"1 switch per group\n\n")

    for r in range(1, num_receivers + 1):
        sw_name = f"SW_{r}"
        first_sid = (r - 1) * senders_per_recv + 1

        # Senders for this receiver
        for j in range(senders_per_recv):
            sid = first_sid + j
            out.write(f"- name: S{sid}\n")
            out.write(f"  type: sender\n")
            out.write(f"  sender_id: {sid}\n")
            out.write(f"  sender_id_bytes: 1\n")
            out.write(f"  max_bandwidth: 25G\n")
            out.write(f"  initial_receiver: R{r}\n")
            out.write(f"  group_id: {sid}\n")
            out.write(f"  connections:\n")
            out.write(f"    1:\n")
            out.write(f"      other_node: {sw_name}\n")
            out.write(f"      other_port: {j + 1}\n")
            out.write(f"      max_bandwidth: 100G\n")
            out.write(f"\n")

        # Switch
        out.write(f"- name: {sw_name}\n")
        out.write(f"  type: switch\n")
        out.write(f"  switch_type_group: tofino2\n")
        out.write(f"  connections:\n")
        for j in range(senders_per_recv):
            sid = first_sid + j
            port = j + 1
            out.write(f"    {port}:\n")
            out.write(f"      other_node: S{sid}\n")
            out.write(f"      other_port: 1\n")
            out.write(f"      max_bandwidth: 100G\n")
        recv_port = senders_per_recv + 1
        out.write(f"    {recv_port}:\n")
        out.write(f"      other_node: R{r}\n")
        out.write(f"      other_port: 1\n")
        out.write(f"      max_bandwidth: 100G\n")
        out.write(f"\n")

        # Receiver
        out.write(f"- name: R{r}\n")
        out.write(f"  type: receiver\n")
        out.write(f"  receiver_id: {r}\n")
        out.write(f"  connections:\n")
        out.write(f"    1:\n")
        out.write(f"      other_node: {sw_name}\n")
        out.write(f"      other_port: {recv_port}\n")
        out.write(f"      max_bandwidth: 100G\n")
        out.write(f"\n")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <num_receivers> <senders_per_receiver> "
              f"<output_file>", file=sys.stderr)
        sys.exit(1)

    R = int(sys.argv[1])
    S = int(sys.argv[2])
    outpath = sys.argv[3]

    if R < 1 or S < 1:
        print("error: num_receivers and senders_per_receiver must be >= 1",
              file=sys.stderr)
        sys.exit(1)

    with open(outpath, "w") as f:
        gen_overhead_topology(R, S, f)
