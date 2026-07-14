#!/usr/bin/env python3
"""
controller_ha.py — main/follower high-availability wrapper for the DiDAQt
network controller.

Two controller nodes run this script.  The MAIN node runs the DiDAQt
controller (examples/controller.c) and sends a small UDP heartbeat to the
FOLLOWER every interval.  The FOLLOWER stays idle, watching for those
heartbeats; if it misses `--miss` of them in a row it concludes the main
has died and takes over by launching the controller itself.

This provides the controller-redundancy piece of the demo.  Data-plane
failover (rerouting senders when a receiver path dies) is handled by the
DiDAQt controller process itself; this wrapper only handles failover of
the controller *node*.

Usage (identical on both nodes except --role/--peer):
  # main controller node
  sudo ./controller_ha.py --role main --peer <follower_ctrl_ip> \
       --hb-port 9100 -- ./build/controller topology.yaml 9000

  # follower controller node
  sudo ./controller_ha.py --role follower --peer <main_ctrl_ip> \
       --hb-port 9100 -- ./build/controller topology.yaml 9000

Everything after `--` is the controller command line to run (or take over).
"""
import argparse
import socket
import subprocess
import sys
import threading
import time

HB_MAGIC = b"DIDAQT-CTRL-HA"
HB_INTERVAL_S = 0.5


def parse_args():
    ap = argparse.ArgumentParser()
    ap.add_argument("--role", choices=["main", "follower"], required=True)
    ap.add_argument("--peer", required=True, help="peer controller IP")
    ap.add_argument("--hb-port", type=int, default=9100,
                    help="UDP port for controller-to-controller heartbeats")
    ap.add_argument("--miss", type=int, default=6,
                    help="missed heartbeats before the follower takes over")
    ap.add_argument("cmd", nargs=argparse.REMAINDER,
                    help="-- <controller command to run>")
    args = ap.parse_args()
    if args.cmd and args.cmd[0] == "--":
        args.cmd = args.cmd[1:]
    if not args.cmd:
        ap.error("provide the controller command after --")
    return args


def send_heartbeats(peer, port, stop):
    """Emit a heartbeat to the peer every interval until stop is set."""
    if ":" not in peer:
        # AF_INET6 sendto rejects dotted-IPv4 destinations outright
        peer = f"::ffff:{peer}"
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    while not stop.is_set():
        try:
            sock.sendto(HB_MAGIC, (peer, port))
        except Exception:  # noqa: BLE001 - peer may be transiently unreachable
            pass
        time.sleep(HB_INTERVAL_S)
    sock.close()


def run_controller(cmd):
    print(f"controller_ha: launching controller: {' '.join(cmd)}", flush=True)
    return subprocess.Popen(cmd)


def run_main(args):
    """Run the controller and heartbeat the follower."""
    stop = threading.Event()
    hb = threading.Thread(target=send_heartbeats,
                          args=(args.peer, args.hb_port, stop), daemon=True)
    hb.start()
    proc = run_controller(args.cmd)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        stop.set()


def run_follower(args):
    """Watch for the main's heartbeats; take over if they stop."""
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("", args.hb_port))
    sock.settimeout(HB_INTERVAL_S)

    print(f"controller_ha[follower]: watching {args.peer} on udp/{args.hb_port} "
          f"(takeover after {args.miss} missed beats)", flush=True)

    misses = 0
    seen_main = False
    while True:
        try:
            data, _ = sock.recvfrom(64)
            if data.startswith(HB_MAGIC):
                if misses:
                    print("controller_ha[follower]: main heartbeat OK", flush=True)
                misses = 0
                seen_main = True
        except socket.timeout:
            if seen_main:
                misses += 1
                if misses >= args.miss:
                    break

    print("controller_ha[follower]: main is DOWN, taking over", flush=True)
    # Become the active controller and start heartbeating in case a third
    # node is watching us.
    stop = threading.Event()
    threading.Thread(target=send_heartbeats,
                     args=(args.peer, args.hb_port, stop), daemon=True).start()
    proc = run_controller(args.cmd)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
    finally:
        stop.set()


def main():
    args = parse_args()
    if args.role == "main":
        run_main(args)
    else:
        run_follower(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
