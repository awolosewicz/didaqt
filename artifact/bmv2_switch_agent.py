#!/usr/bin/env python3
"""
bmv2_switch_agent.py — BMv2 counterpart of switch_agent.py.

Runs on an AttestableSwitch (BMv2 / simple_switch) node.  Installs the
initial l2_forward rules and then listens for ICMPv6 echo requests from
the DiDAQt controller, translating them into runtime table operations via
`simple_switch_CLI` (the same CLI that fablib's
Attestable_Switch.run_command() drives).

This mirrors the Tofino agent's control protocol exactly so the stock
DiDAQt controller (examples/controller.c) can talk to either target
unchanged:

  Controller -> ICMPv6 echo request (type 128), identifier 0xDDAA,
                payload = command string (e.g. "UPDATE 1 -1 2 -1 3")
  Agent      -> ICMPv6 echo reply   (type 129), same id + seq,
                payload = "OK <us>" / "ERR <msg>" / "PONG"

Commands:
  PING                                  -> PONG
  KA                                    -> OK        (silent keepalive)
  QUIT                                  -> OK bye    (stops the agent)
  UPDATE <sid> <cin> <cout> <nin> <nout>
        Re-point the entry currently egressing on BMv2 port <cout> to
        BMv2 port <nout>.  Ingress ports are ignored (dst-MAC forwarding).

The l2_forward entries are keyed on destination MAC, so the agent keeps a
port -> (dst_mac, ...) map (built from the rules file) and rewrites the
matching entry on failover, exactly like the Tofino agent's fwd_table.

Reachability bring-up does NOT need this agent — the notebook installs the
static forwarding rules directly.  It is the control plane for the later
failover phase.

Run on the switch node (needs root for the raw ICMPv6 socket):
  sudo P4_TABLE=MyIngress.l2_forward python3 bmv2_switch_agent.py \
       /tmp/bmv2_rules.json

Rules file format (written by the notebook), one entry per initial route:
  [{"dst_mac": "aa:bb:cc:dd:ee:ff", "port": 2}, ...]
"""
import json
import os
import socket
import struct
import subprocess
import sys
import time

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
DIDAQT_ICMP_ID = 0xDDAA
STOP_FILE = "/tmp/bmv2_switch_agent_stop"

# Fully qualified table name as shown by `show_tables` in simple_switch_CLI.
TABLE = os.environ.get("P4_TABLE", "MyIngress.l2_forward")

RULES_CONF = sys.argv[1] if len(sys.argv) > 1 else "/tmp/bmv2_rules.json"

# Clean up a stale stop file from a previous run.
if os.path.exists(STOP_FILE):
    os.unlink(STOP_FILE)


def mac_to_hex(mac):
    """'aa:bb:cc:dd:ee:ff' -> '0xaabbccddeeff' for simple_switch_CLI."""
    return "0x" + mac.replace(":", "").lower()


def cli(command):
    """Run one simple_switch_CLI command; return (ok, output)."""
    try:
        proc = subprocess.run(
            ["simple_switch_CLI"],
            input=command + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception as e:  # noqa: BLE001 - report any launch failure verbatim
        return False, str(e)
    out = proc.stdout + proc.stderr
    ok = "RuntimeCmd: Error" not in out and proc.returncode == 0
    return ok, out.strip()


# ---- Install initial forwarding rules ----
# port -> (dst_mac, handle).  handle is the simple_switch_CLI entry handle,
# needed for table_modify on failover.
fwd_table = {}

if os.path.exists(RULES_CONF):
    with open(RULES_CONF) as f:
        rules = json.load(f)
    for rule in rules:
        dst = rule["dst_mac"]
        port = int(rule["port"])
        ok, out = cli(f"table_add {TABLE} forward {mac_to_hex(dst)} => {port}")
        if not ok:
            print(f"  ERROR adding dst={dst} port={port}: {out}")
            continue
        # simple_switch_CLI prints "Entry has been added with handle N".
        handle = None
        for tok in out.split():
            if tok.isdigit():
                handle = int(tok)
        fwd_table[port] = (dst, handle)
        print(f"  rule: dst={dst} -> port={port} (handle {handle})")
    print(f"bmv2_switch_agent: {len(fwd_table)} forwarding rules installed")
else:
    print(f"bmv2_switch_agent: WARNING: {RULES_CONF} not found, no rules installed")


def handle_update(sender_id, cur_in, cur_out, new_in, new_out):
    """Re-point the entry on BMv2 port cur_out to new_out."""
    t0 = time.monotonic()
    if cur_out < 0 or cur_out not in fwd_table:
        return False, f"no entry for egress port {cur_out}"
    if new_out < 0:
        return False, "invalid new egress port"

    dst, handle = fwd_table[cur_out]
    if handle is not None:
        ok, out = cli(f"table_modify {TABLE} forward {handle} {new_out}")
    else:
        # Fall back to delete + add if we never learned the handle.
        cli(f"table_delete {TABLE} 0")
        ok, out = cli(f"table_add {TABLE} forward {mac_to_hex(dst)} => {new_out}")
    if not ok:
        return False, out

    del fwd_table[cur_out]
    fwd_table[new_out] = (dst, handle)
    elapsed_us = int((time.monotonic() - t0) * 1e6)
    print(f"  UPDATE sender={sender_id} dst={dst} egress {cur_out}->{new_out} "
          f"{elapsed_us}us")
    return True, str(elapsed_us)


def handle_command(cmd):
    """Process a command string, return (response, should_quit)."""
    parts = cmd.split()
    if not parts:
        return "ERR empty", False
    if parts[0] == "KA":
        return "OK", False
    if parts[0] == "PING":
        return "PONG", False
    if parts[0] == "QUIT":
        return "OK bye", True
    if parts[0] == "UPDATE" and len(parts) == 6:
        try:
            sid, ci, co, ni, no = (int(x) for x in parts[1:6])
        except ValueError:
            return "ERR bad params", False
        ok, msg = handle_update(sid, ci, co, ni, no)
        return (f"OK {msg}" if ok else f"ERR {msg}"), False
    return "ERR bad command", False


# ---- ICMPv6 control channel ----
sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.settimeout(5.0)

print(f"bmv2_switch_agent: listening for ICMPv6 (id=0x{DIDAQT_ICMP_ID:04X}), "
      f"table={TABLE}")
print(f"bmv2_switch_agent: send QUIT or 'touch {STOP_FILE}' to exit")

running = True
while running:
    if os.path.exists(STOP_FILE):
        print("bmv2_switch_agent: stop file detected, exiting")
        break
    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        continue
    except Exception as e:  # noqa: BLE001
        print(f"bmv2_switch_agent: recv error: {e}")
        time.sleep(1)
        continue

    if len(data) < 8 or data[0] != ICMP6_ECHO_REQUEST:
        continue
    ident = struct.unpack("!H", data[4:6])[0]
    if ident != DIDAQT_ICMP_ID:
        continue
    seq = struct.unpack("!H", data[6:8])[0]
    payload = data[8:].decode("utf-8", errors="replace").strip().strip("\x00")
    silent = payload == "KA"

    if not silent:
        print(f"  recv: seq={seq} cmd='{payload}' from {addr[0]}")

    response, quit_flag = handle_command(payload)

    reply = struct.pack("!BBHHH", ICMP6_ECHO_REPLY, 0, 0, DIDAQT_ICMP_ID, seq)
    reply += response.encode("utf-8")
    try:
        sock.sendto(reply, addr)
    except Exception as e:  # noqa: BLE001
        print(f"bmv2_switch_agent: sendto error: {e}")

    if not silent:
        print(f"  sent: seq={seq} resp='{response}' to {addr[0]}")
    if quit_flag:
        running = False

sock.close()
print("bmv2_switch_agent: stopped")
