"""
switch_agent.py — Runs inside bfrt_python on the Tofino switch.

Listens for ICMPv6 echo requests from the DiDAQt controller and
translates them into bfrt table operations on the l2_forward table.
Uses ICMPv6 because FABRIC's management plane allows ICMP but blocks
arbitrary TCP/UDP between nodes.

Protocol:
  Controller sends ICMPv6 echo request (type 128) with:
    - Identifier: 0xDDAA
    - Payload: command string (e.g., "UPDATE 1 1 3 1 4")
  Agent sends ICMPv6 echo reply (type 129) with:
    - Same identifier and sequence
    - Payload: response (e.g., "OK 1234" or "PONG")

The kernel also auto-replies with the original payload echoed back;
the controller distinguishes agent replies by payload prefix.

To stop the agent (since ctrl-c is intercepted by switchd):
  - Send a QUIT command via ICMPv6 from the controller
  - Or: touch /tmp/switch_agent_stop

Run with (inside bfshell session):
  bfrt_python /tmp/switch_agent.py

Requires root (raw sockets).
"""
import socket
import struct
import time
import os

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
DIDAQT_ICMP_ID = 0xDDAA
STOP_FILE = '/tmp/switch_agent_stop'

# Clean up stale stop file from previous runs.
if os.path.exists(STOP_FILE):
    os.unlink(STOP_FILE)

# ---- Discover port mapping (logical name -> dev_port) ----
port_dump = bfrt.port.port.dump(return_ents=True)
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

def handle_update(sender_id, cur_in, cur_out, new_in, new_out):
    """Apply a forwarding table change for a failover."""
    t0 = time.monotonic()

    dev_new_out = resolve_port(new_out)
    dev_cur_out = resolve_port(cur_out) if cur_out >= 0 else None

    if dev_new_out is None:
        return False, "unknown new egress port"

    try:
        entries = l2_fwd.dump(return_ents=True, from_hw=True)
        modified = False
        if entries and dev_cur_out is not None:
            for ent in entries:
                port_val = ent.data.get('port') or ent.data.get(b'port')
                if port_val == dev_cur_out:
                    dst = ent.key.get('dst_addr') or ent.key.get(b'dst_addr')
                    vlan = ent.data.get('vlan_id', ent.data.get(b'vlan_id', 0))
                    # bfrt_python has no .mod(); delete + re-add.
                    l2_fwd.delete(dst_addr=dst)
                    l2_fwd.add_with_forward(
                        dst_addr=dst,
                        port=dev_new_out,
                        vlan_id=vlan
                    )
                    modified = True
                    break

        bfrt.complete_operations()
        elapsed_us = int((time.monotonic() - t0) * 1e6)

        action = "modified" if modified else "no matching entry"
        print(f"  UPDATE sender={sender_id} egress {cur_out}->{new_out} "
              f"(dev {dev_cur_out}->{dev_new_out}) [{action}] {elapsed_us}us")
        return True, str(elapsed_us)

    except Exception as e:
        return False, str(e)

def handle_command(cmd):
    """Process a command string, return (response_string, should_quit)."""
    parts = cmd.split()
    if not parts:
        return "ERR empty", False

    if parts[0] == 'PING':
        return 'PONG', False

    if parts[0] == 'QUIT':
        return 'OK bye', True

    if parts[0] == 'UPDATE' and len(parts) == 6:
        sid    = int(parts[1])
        ci     = int(parts[2])
        co     = int(parts[3])
        ni     = int(parts[4])
        no     = int(parts[5])
        ok, msg = handle_update(sid, ci, co, ni, no)
        return (f'OK {msg}' if ok else f'ERR {msg}'), False

    return 'ERR bad command', False

# ---- ICMPv6 raw socket ----
sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sock.settimeout(5.0)  # check stop file periodically

print(f"switch_agent: listening for ICMPv6 echo requests (id=0x{DIDAQT_ICMP_ID:04X})")
print(f"switch_agent: send QUIT command or 'touch {STOP_FILE}' to exit")

agent_running = True
while agent_running:
    # Check stop file
    if os.path.exists(STOP_FILE):
        print("switch_agent: stop file detected, exiting")
        break

    try:
        data, addr = sock.recvfrom(4096)
    except socket.timeout:
        continue
    except Exception:
        continue

    if len(data) < 8:
        continue

    # Parse ICMPv6 header
    icmp_type = data[0]
    if icmp_type != ICMP6_ECHO_REQUEST:
        continue

    ident = struct.unpack('!H', data[4:6])[0]
    if ident != DIDAQT_ICMP_ID:
        continue

    seq = struct.unpack('!H', data[6:8])[0]
    payload = data[8:].decode('utf-8', errors='replace').strip()

    print(f"  recv: seq={seq} cmd='{payload}' from {addr[0]}")

    # Process command
    response, quit_flag = handle_command(payload)

    # Build echo reply: type=129, code=0, cksum=0 (kernel fills),
    # same id and seq, response as payload.
    reply = struct.pack('!BBHHH',
                        ICMP6_ECHO_REPLY, 0, 0,
                        DIDAQT_ICMP_ID, seq)
    reply += response.encode('utf-8')

    sock.sendto(reply, addr)
    print(f"  sent: seq={seq} resp='{response}' to {addr[0]}")

    if quit_flag:
        print("switch_agent: QUIT received, exiting")
        agent_running = False

sock.close()
print("switch_agent: stopped")
