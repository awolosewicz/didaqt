"""
switch_agent.py — Runs inside bfrt_python on the Tofino switch.

Installs initial L2 forwarding rules, then listens for ICMPv6 echo
requests from the DiDAQt controller and translates them into bfrt
table operations.  Runs as a single bfrt_python session so the
agent can see the entries it installed (avoids cross-session cache
issues).

Protocol:
  Controller sends ICMPv6 echo request (type 128) with:
    - Identifier: 0xDDAA
    - Payload: command string (e.g., "UPDATE 1 1 3 1 4")
  Agent sends ICMPv6 echo reply (type 129) with:
    - Same identifier and sequence
    - Payload: response (e.g., "OK 1234" or "PONG")

To stop the agent (since ctrl-c is intercepted by switchd):
  - Send a QUIT command via ICMPv6 from the controller
  - Or: touch /tmp/switch_agent_stop

Run with (inside bfshell session, after enabling ports):
  bfrt_python /tmp/switch_agent.py

Requires root (raw sockets).
"""
import socket
import struct
import time
import os
import io
import sys
import json

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
DIDAQT_ICMP_ID = 0xDDAA
STOP_FILE = '/tmp/switch_agent_stop'
RULES_CONF = '/tmp/switch_agent_rules.json'

# Clean up stale stop file from previous runs.
if os.path.exists(STOP_FILE):
    os.unlink(STOP_FILE)

# ---- Discover port mapping (logical name -> dev_port) ----
port_dump = None
_old_stdout = sys.stdout
sys.stdout = io.StringIO()
try:
    port_dump = bfrt.port.port.dump(return_ents=True)
finally:
    sys.stdout = _old_stdout

port_map = {}
if port_dump:
    for ent in port_dump:
        dp = ent.key.get('$DEV_PORT') or ent.key.get(b'$DEV_PORT')
        pname = ent.data.get('$PORT_NAME') or ent.data.get(b'$PORT_NAME', '')
        if isinstance(pname, bytes):
            pname = pname.decode()
        connector = str(pname).split('/')[0]
        port_map[connector] = dp

print(f"switch_agent: port mapping = {port_map}")

# ---- Get forwarding table handle ----
l2_fwd = bfrt.l2_forward.pipe.Ingress.l2_forward

def resolve_port(logical):
    """Map a logical port number to a Tofino dev_port."""
    return port_map.get(str(logical))

# ---- Install initial forwarding rules ----
# Rules config is a JSON file written by the notebook:
#   [{"logical_port": "3", "dst_addr": 1234567890, "vlan_id": 0}, ...]
fwd_table = {}   # dev_port -> (dst_addr_int, vlan_id)

if os.path.exists(RULES_CONF):
    with open(RULES_CONF) as f:
        rules = json.load(f)
    for rule in rules:
        dp = resolve_port(rule['logical_port'])
        if dp is None:
            print(f"  WARNING: unknown logical port {rule['logical_port']}")
            continue
        dst = rule['dst_addr']
        vid = rule.get('vlan_id', 0)
        try:
            l2_fwd.add_with_forward(dst_addr=dst, port=dp, vlan_id=vid)
        except Exception as e:
            # Entry may already exist from a previous run; try delete+add.
            try:
                l2_fwd.delete(dst_addr=dst)
                l2_fwd.add_with_forward(dst_addr=dst, port=dp, vlan_id=vid)
            except Exception as e2:
                print(f"  ERROR adding rule dst=0x{dst:x} port={dp}: {e2}")
                continue
        fwd_table[dp] = (dst, vid)
        print(f"  rule: dst=0x{dst:x} -> port={dp} (logical {rule['logical_port']}) vlan={vid}")
    bfrt.complete_operations()
    print(f"switch_agent: {len(fwd_table)} forwarding rules installed")
else:
    print(f"switch_agent: WARNING: {RULES_CONF} not found, no rules installed")

l2_fwd.dump(table=True)

# ---- Update handler ----

def handle_update(sender_id, cur_in, cur_out, new_in, new_out):
    """Apply a forwarding table change for a failover."""
    t0 = time.monotonic()

    dev_new_out = resolve_port(new_out)
    dev_cur_out = resolve_port(cur_out) if cur_out >= 0 else None

    if dev_new_out is None:
        return False, "unknown new egress port"

    if dev_cur_out is None or dev_cur_out not in fwd_table:
        return False, f"no entry for dev_port {dev_cur_out}"

    try:
        dst, vlan = fwd_table[dev_cur_out]

        l2_fwd.delete(dst_addr=dst)
        l2_fwd.add_with_forward(
            dst_addr=dst,
            port=dev_new_out,
            vlan_id=vlan
        )
        bfrt.complete_operations()

        del fwd_table[dev_cur_out]
        fwd_table[dev_new_out] = (dst, vlan)

        elapsed_us = int((time.monotonic() - t0) * 1e6)
        print(f"  UPDATE sender={sender_id} dst=0x{dst:x} "
              f"egress {cur_out}->{new_out} "
              f"(dev {dev_cur_out}->{dev_new_out}) {elapsed_us}us")
        return True, str(elapsed_us)

    except Exception as e:
        return False, str(e)

def handle_command(cmd):
    """Process a command string, return (response_string, should_quit)."""
    parts = cmd.split()
    if not parts:
        return "ERR empty", False

    if parts[0] == 'KA':
        return 'OK', False    # keepalive — silent, no log

    if parts[0] == 'PING':
        return 'PONG', False

    if parts[0] == 'QUIT':
        return 'OK bye', True

    if parts[0] == 'UPDATE' and len(parts) == 6:
        try:
            sid    = int(parts[1])
            ci     = int(parts[2])
            co     = int(parts[3])
            ni     = int(parts[4])
            no     = int(parts[5])
        except ValueError:
            return 'ERR bad params', False
        ok, msg = handle_update(sid, ci, co, ni, no)
        return (f'OK {msg}' if ok else f'ERR {msg}'), False

    return 'ERR bad command', False

# ---- ICMPv6 raw socket ----
sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.settimeout(5.0)

print(f"switch_agent: listening for ICMPv6 echo requests (id=0x{DIDAQT_ICMP_ID:04X})")
print(f"switch_agent: send QUIT command or 'touch {STOP_FILE}' to exit")

agent_running = True
while agent_running:
    if os.path.exists(STOP_FILE):
        print("switch_agent: stop file detected, exiting")
        break

    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        continue
    except Exception as e:
        print(f"switch_agent: recv error: {e}")
        time.sleep(1)
        continue

    if len(data) < 8:
        continue

    icmp_type = data[0]
    if icmp_type != ICMP6_ECHO_REQUEST:
        continue

    ident = struct.unpack('!H', data[4:6])[0]
    if ident != DIDAQT_ICMP_ID:
        continue

    seq = struct.unpack('!H', data[6:8])[0]
    payload = data[8:].decode('utf-8', errors='replace').strip().strip('\x00')

    silent = payload == 'KA'

    if not silent:
        print(f"  recv: seq={seq} cmd='{payload}' from {addr[0]}")

    response, quit_flag = handle_command(payload)

    reply = struct.pack('!BBHHH',
                        ICMP6_ECHO_REPLY, 0, 0,
                        DIDAQT_ICMP_ID, seq)
    reply += response.encode('utf-8')

    try:
        sock.sendto(reply, addr)
    except Exception as e:
        print(f"switch_agent: sendto error: {e}")

    if not silent:
        print(f"  sent: seq={seq} resp='{response}' to {addr[0]}")

    if quit_flag:
        print("switch_agent: QUIT received, exiting")
        agent_running = False

sock.close()
print("switch_agent: stopped")
