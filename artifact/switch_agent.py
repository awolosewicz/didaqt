"""
switch_agent.py — Runs inside bfrt_python on the Tofino switch.

Listens for TCP commands from the DiDAQt controller and translates
them into bfrt table operations on the l2_forward table.

Protocol (newline-delimited):
  Controller sends:  UPDATE <sender_id> <cur_in> <cur_out> <new_in> <new_out>
  Agent responds:    OK <elapsed_us>
                     ERR <message>

Run with:
  run_bfshell.sh --no-status-srv -b /path/to/switch_agent.py

The agent runs indefinitely, accepting multiple sequential connections.
"""
import socket
import time

AGENT_PORT = 9200

# ---- Discover port mapping (logical name -> dev_port) ----
port_dump = bfrt.port.port.dump(return_ents=True, from_hw=True)
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
    """
    Apply a forwarding table change for a failover.

    For our L2 forwarding table (keyed by dst_mac), this performs
    the table modification needed to reroute traffic.  The exact
    operation depends on which ports changed.
    """
    t0 = time.monotonic()

    dev_new_out = resolve_port(new_out)
    dev_cur_out = resolve_port(cur_out) if cur_out >= 0 else None

    if dev_new_out is None:
        return False, "unknown new egress port"

    # For the evaluation, perform a table read+modify cycle to
    # measure real hardware latency.  In a full implementation this
    # would do the specific add/modify/delete operations.
    try:
        # Read current entries to find the one using the old egress.
        entries = l2_fwd.dump(return_ents=True, from_hw=True)
        modified = False
        if entries and dev_cur_out is not None:
            for ent in entries:
                port_val = ent.data.get('port') or ent.data.get(b'port')
                if port_val == dev_cur_out:
                    # Modify this entry to point to the new egress.
                    dst = ent.key.get('dst_addr') or ent.key.get(b'dst_addr')
                    l2_fwd.mod(
                        dst_addr=dst,
                        port=dev_new_out,
                        vlan_id=ent.data.get('vlan_id', ent.data.get(b'vlan_id', 0))
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

# ---- TCP server ----
srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    srv.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
except Exception:
    pass
srv.bind(('::', AGENT_PORT))
srv.listen(4)
print(f"switch_agent: listening on TCP port {AGENT_PORT}")

while True:
    conn, addr = srv.accept()
    print(f"switch_agent: connection from {addr}")
    buf = b''
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            buf += data
            while b'\n' in buf:
                line, buf = buf.split(b'\n', 1)
                cmd = line.decode().strip()
                if not cmd:
                    continue
                parts = cmd.split()
                if parts[0] == 'UPDATE' and len(parts) == 6:
                    sid   = int(parts[1])
                    ci    = int(parts[2])
                    co    = int(parts[3])
                    ni    = int(parts[4])
                    no    = int(parts[5])
                    ok, msg = handle_update(sid, ci, co, ni, no)
                    if ok:
                        conn.sendall(f'OK {msg}\n'.encode())
                    else:
                        conn.sendall(f'ERR {msg}\n'.encode())
                elif parts[0] == 'PING':
                    conn.sendall(b'PONG\n')
                else:
                    conn.sendall(b'ERR bad command\n')
    except Exception as e:
        print(f"switch_agent: connection error: {e}")
    finally:
        conn.close()
        print(f"switch_agent: connection closed")
