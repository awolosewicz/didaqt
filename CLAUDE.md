# DiDAQt

C library providing fault detection and warm fail-over for unidirectional DAQ (Data Acquisition) networks.

## Build

```bash
make          # builds build/libdidaqt.a
make examples # builds sender, receiver, controller, heartbeat_monitor in build/
make clean
```

Requires: `gcc`, `libyaml-dev`, `pthreads` (Linux only — uses AF_PACKET, raw sockets).

## Project structure

```
include/didaqt.h       Public API (receiver + controller)
src/didaqt_rx.c        Receiver: heartbeat scheduling, background UDP sender
src/didaqt_ctrl.c      Controller: YAML topology parsing, path finding, failover state machine
examples/sender.c      Raw AF_PACKET sender with VLAN support and fault injection (-f, -o)
examples/receiver.c    Raw AF_PACKET receiver with DiDAQt heartbeats and TUI
examples/controller.c  Controller with ICMPv6 switch communication and TUI
examples/topology.yaml Example topology (10 senders, 1 switch, 2 receivers)
examples/p4/           Tofino 2 P4 program (VLAN-aware L2 forwarding)
artifact/              FABRIC testbed notebook and switch agent
```

## Code conventions

- C11, compiled with `-Wall -Wextra -Werror`
- Use `__attribute__((unused))` for intentionally unused parameters (not `(void)`)
- No unnecessary output: senders print only on start/stop, receivers only on faults, controller only on failover events
- Screen-refreshing TUIs use ANSI escape codes (`\033[H` home, `\033[K` clear line, `\033[J` clear below)

## Architecture

**Receiver side** (`didaqt_rx`): User calls `schedule_heartbeat(s_id)` on valid frames, `deschedule_heartbeat(s_id)` on invalid frames. Deschedule blocks the sender for the remainder of the heartbeat interval. Background thread sends UDP heartbeats to the controller every interval.

**Controller side** (`didaqt_ctrl`): Parses YAML topology, runs DFS to find all sender→receiver paths through switches, orders by contention then switch updates. Runtime processes heartbeats and triggers failover when senders go missing. Group failover moves all senders in a group atomically with one switch update. Dead senders auto-revive when they reappear in heartbeats.

**Switch communication**: ICMPv6 echo request/reply with identifier 0xDDAA (FABRIC management plane blocks TCP/UDP between nodes but allows ICMP). Controller sends keepalives every 1s to prevent cold-path latency spikes.

## FABRIC artifact

The Jupyter notebook (`artifact/didaqt_experiment.ipynb`) creates a FABRIC testbed with sender, receiver, controller nodes and a Tofino P4 switch.

Key patterns for the notebook:
- All constants in the first config cell (for notebook resume)
- Parallel node operations use `_thread` + `futures.as_completed`
- Switch home is `/home/fabric` not `/home/ubuntu` — use relative paths
- Switch prompt regex must match full line: `r'.*nix-shell.*'` and `r'.*fabric@p4switch.*'`
- `sde-env-9.13.3` only works in interactive login shell (tuple-based execute)
- `make examples` for compilation, not per-target builds
- `switch_agent.py` runs in bfrt_python: installs rules + listens for ICMPv6 commands in one session

## Key types

```
didaqt_path_status: USED, AVAILABLE, TEMP_FAILED, FAILED
```

Failover flow: USED → TEMP_FAILED (on miss) → FAILED (confirmed by heartbeat from new receiver). FAILED paths are recycled to AVAILABLE when no other paths remain. TEMP_FAILED paths are never recycled during normal failover (all TempFailed = sender dead), but are reset to AVAILABLE when a dead sender is revived via auto-revival.

## Testing the example

1. Run notebook cells through switch configuration
2. SSH into switch, run switchd + `bfrt_python /tmp/switch_agent.py`
3. Start controller: `sudo ./build/controller [-m miss] [-g grace_ms] topology.yaml 9000 [switch_ipv6]`
4. Start receivers: `sudo ./build/receiver [-i interval_ms] <iface> <id> <ctrl_ip> 9000`
5. Start senders: `sudo ./build/sender <iface> <dst_mac> <id>`
6. Inject fault: `sudo ./build/sender -o <iface> <dst_mac> <id>` (one bad packet)
