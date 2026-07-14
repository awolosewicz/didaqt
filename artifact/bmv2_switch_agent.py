#!/usr/bin/env python3
"""
bmv2_switch_agent.py -- DiDAQt switch agent for BMv2 nodes.

Runs on each BMv2 switch node, listens for ICMPv6 echo requests from
the DiDAQt controller (FABRIC's management plane blocks TCP/UDP between
nodes but allows ICMP) and translates UPDATE commands into l2_forward
table operations on the local simple_switch via a persistent
simple_switch_CLI child (a fresh CLI invocation costs ~0.5s in
thrift/JSON setup; the persistent pipe keeps updates at ms scale).

Protocol (controller.c agent-map mode, -s switches.map):
  Controller sends ICMPv6 echo request (type 128) with:
    - Identifier: 0xDDAA
    - Payload: "UPDATE <switch_name> <sender_id> <cur_in> <cur_out>
       <new_in> <new_out>" (ports are 1-based topology.yaml numbers;
       BMv2 port index = port - 1), or "PING" / "KA" / "QUIT"
  Agent sends ICMPv6 echo reply (type 129) with the same identifier
  and sequence and payload "OK ..." / "ERR ..." / "PONG".

The forwarding table is keyed by each sender's constant routing MAC
(the frame source field, see examples/p4/l2_forward_bmv2.p4), given in
the config file.  UPDATE with new_out >= 0 re-points that MAC's entry
(table_modify, or table_add on switches that have no entry for it yet);
new_out == -1 (pure remove) is a no-op -- the stale entry is
unreachable once upstream switches are re-pointed.

UPDATE always gets an OK reply, even if the local switch is dead:
didaqt_ctrl rolls the failover back if any switch update is NACKed,
which would loop forever when the failed path's own switch is the dead
one.  DiDAQt detects dead switches through data-plane heartbeats, not
through update NACKs; errors are logged here instead.

Config file (one directive per line):
  name sw2n1
  thrift_port 9090
  table MyIngress.l2_forward
  sender 1 8A:5B:30:E4:F1:2A
  ...

Usage:
  sudo python3 bmv2_switch_agent.py <conf_file>

To stop: send QUIT via ICMPv6, or 'touch /tmp/bmv2_switch_agent_stop'.
Requires root (raw sockets).
"""
import os
import re
import socket
import struct
import subprocess
import sys
import time

ICMP6_ECHO_REQUEST = 128
ICMP6_ECHO_REPLY = 129
DIDAQT_ICMP_ID = 0xDDAA
STOP_FILE = '/tmp/bmv2_switch_agent_stop'
CLI_PROMPT = 'RuntimeCmd: '


def read_conf(path):
    conf = {'name': None, 'thrift_port': '9090',
            'table': 'MyIngress.l2_forward', 'senders': {}}
    with open(path) as f:
        for line in f:
            parts = line.split()
            if not parts or parts[0].startswith('#'):
                continue
            if parts[0] == 'sender' and len(parts) == 3:
                conf['senders'][int(parts[1])] = parts[2].lower()
            elif parts[0] in ('name', 'thrift_port', 'table') and len(parts) == 2:
                conf[parts[0]] = parts[1]
    if not conf['name'] or not conf['senders']:
        raise SystemExit(f"bmv2_switch_agent: incomplete config {path}")
    return conf


class CLI:
    """Persistent simple_switch_CLI child; one command per call."""

    def __init__(self, thrift_port):
        self.thrift_port = thrift_port
        self.proc = None

    def _spawn(self):
        self.proc = subprocess.Popen(
            ['simple_switch_CLI', '--thrift-port', self.thrift_port],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=0,
            env=dict(os.environ, PYTHONUNBUFFERED='1'))
        self._read_to_prompt()

    def _read_to_prompt(self):
        buf = ''
        while not buf.endswith(CLI_PROMPT):
            c = self.proc.stdout.read(1)
            if not c:
                raise BrokenPipeError('CLI exited')
            buf += c
        return buf[:-len(CLI_PROMPT)]

    def run(self, cmd):
        """Return the command's output, respawning the child once if dead."""
        for attempt in (0, 1):
            try:
                if self.proc is None or self.proc.poll() is not None:
                    self._spawn()
                self.proc.stdin.write(cmd + '\n')
                self.proc.stdin.flush()
                return self._read_to_prompt()
            except (BrokenPipeError, OSError) as e:
                self.proc = None
                if attempt:
                    raise BrokenPipeError(f'CLI unavailable: {e}')


def main():
    # Line-buffer stdout so the log stays readable while running detached
    # (block buffering holds startup lines back indefinitely).
    sys.stdout.reconfigure(line_buffering=True)
    if len(sys.argv) != 2:
        raise SystemExit("Usage: sudo python3 bmv2_switch_agent.py <conf_file>")
    conf = read_conf(sys.argv[1])
    name, table = conf['name'], conf['table']
    cli = CLI(conf['thrift_port'])

    if os.path.exists(STOP_FILE):
        os.unlink(STOP_FILE)

    # MAC (lowercase, no colons) -> entry handle, learned from the running
    # table and kept current across our own adds.
    handles = {}

    def load_handles():
        handles.clear()
        out = cli.run(f'table_dump {table}')
        cur = None
        for line in out.splitlines():
            m = re.search(r'Dumping entry 0x([0-9a-f]+)', line)
            if m:
                cur = int(m.group(1), 16)
                continue
            m = re.search(r'EXACT\s+([0-9a-f]+)', line)
            if m and cur is not None:
                handles[m.group(1)] = cur
                cur = None
        print(f"bmv2_switch_agent[{name}]: {len(handles)} entries in {table}: {handles}")

    try:
        load_handles()
    except BrokenPipeError as e:
        print(f"bmv2_switch_agent[{name}]: WARNING: switch unreachable at startup ({e})")

    def handle_update(sid, new_out):
        t0 = time.monotonic()
        mac = conf['senders'].get(sid)
        if mac is None:
            print(f"  UPDATE sender={sid}: unknown sender id")
            return 'OK unknown-sender'
        if new_out < 0:
            return 'OK noop'
        port = new_out - 1
        key = mac.replace(':', '')
        try:
            if key in handles:
                out = cli.run(f'table_modify {table} forward {handles[key]} {port}')
            else:
                out = cli.run(f'table_add {table} forward {mac} => {port}')
                m = re.search(r'handle (\d+)', out)
                if m:
                    handles[key] = int(m.group(1))
            err = [l for l in out.splitlines() if 'Error' in l or 'Invalid' in l]
            us = int((time.monotonic() - t0) * 1e6)
            print(f"  UPDATE sender={sid} mac={mac} -> port {port} {us}us"
                  + (f" CLI-ERROR: {err}" if err else ""))
            return f'OK {us}' if not err else 'OK cli-error'
        except BrokenPipeError as e:
            print(f"  UPDATE sender={sid}: switch dead ({e})")
            return 'OK dead'

    def handle_command(cmd):
        parts = cmd.split()
        if not parts:
            return 'ERR empty', False
        if parts[0] == 'KA':
            return 'OK', False
        if parts[0] == 'PING':
            return 'PONG', False
        if parts[0] == 'QUIT':
            return 'OK bye', True
        if parts[0] == 'UPDATE' and len(parts) == 7:
            if parts[1] != name:
                print(f"  MISROUTED update for {parts[1]} (this is {name}), ignored")
                return 'OK misrouted', False
            try:
                sid, new_out = int(parts[2]), int(parts[6])
            except ValueError:
                return 'ERR bad params', False
            return handle_update(sid, new_out), False
        return 'ERR bad command', False

    sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    sock.settimeout(5.0)
    print(f"bmv2_switch_agent[{name}]: listening for ICMPv6 echo requests "
          f"(id=0x{DIDAQT_ICMP_ID:04X})")

    running = True
    while running:
        if os.path.exists(STOP_FILE):
            print(f"bmv2_switch_agent[{name}]: stop file detected, exiting")
            break
        try:
            data, addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except Exception as e:
            print(f"bmv2_switch_agent[{name}]: recv error: {e}")
            time.sleep(1)
            continue

        if len(data) < 8 or data[0] != ICMP6_ECHO_REQUEST:
            continue
        if struct.unpack('!H', data[4:6])[0] != DIDAQT_ICMP_ID:
            continue
        seq = struct.unpack('!H', data[6:8])[0]
        payload = data[8:].decode('utf-8', errors='replace').strip().strip('\x00')

        silent = payload == 'KA'
        if not silent:
            print(f"  recv: seq={seq} cmd='{payload}' from {addr[0]}")

        response, quit_flag = handle_command(payload)
        reply = struct.pack('!BBHHH', ICMP6_ECHO_REPLY, 0, 0,
                            DIDAQT_ICMP_ID, seq) + response.encode('utf-8')
        try:
            sock.sendto(reply, addr)
        except Exception as e:
            print(f"bmv2_switch_agent[{name}]: sendto error: {e}")
        if not silent:
            print(f"  sent: seq={seq} resp='{response}' to {addr[0]}")
        if quit_flag:
            running = False

    sock.close()
    print(f"bmv2_switch_agent[{name}]: stopped")


if __name__ == '__main__':
    main()
