/*
 * l2_forward_bmv2.p4 — VLAN-aware L2 MAC forwarding for BMv2 (v1model).
 *
 * The software-switch counterpart of examples/p4/l2_forward.p4 (which
 * targets Tofino 2 / TNA).  Parses Ethernet and an optional 802.1Q VLAN
 * header, then does an exact match on the SOURCE MAC address to pick an
 * egress port.
 *
 * In the butterfly demo frames are sent to the broadcast MAC and carry
 * the routing MAC (the target receiver's NIC MAC) in the source field
 * (sender -b).  Unicast destinations cannot be used on fabrics whose
 * SR-IOV NICs silently drop frames addressed to MACs they do not own
 * (e.g. FABRIC shared NICs); broadcast destinations always pass, so the
 * routing key moves to the source field.  Butterfly self-routing is
 * unchanged: at each rank, the entry for a given routing MAC points at
 * the "straight" or "cross" egress port according to the relevant bit
 * of the receiver index.  The notebook (or the bmv2 switch agent)
 * populates and updates the "l2_forward" table at runtime via
 * simple_switch_CLI.
 *
 * Unlike the Tofino program this does NOT rewrite the VLAN id: with
 * single-site L2Bridge links each hop is an untagged access port, so the
 * VLAN header is parsed only so it can be re-emitted unchanged if present.
 *
 * Compile on the switch node with:
 *   p4c --target bmv2 --arch v1model l2_forward_bmv2.p4
 */

#include <core.p4>
#include <v1model.p4>

/* ---------- Headers ---------- */

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header vlan_tag_h {
    bit<3>  pcp;
    bit<1>  dei;
    bit<12> vid;
    bit<16> ether_type;
}

struct headers_t {
    ethernet_h ethernet;
    vlan_tag_h vlan;
}

struct metadata_t {}

const bit<16> ETHERTYPE_VLAN = 0x8100;

/* ---------- Parser ---------- */

parser MyParser(
        packet_in pkt,
        out headers_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t std_meta) {

    state start {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_VLAN : parse_vlan;
            default        : accept;
        }
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition accept;
    }
}

/* ---------- Checksum verification (none needed) ---------- */

control MyVerifyChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

/* ---------- Ingress ---------- */

control MyIngress(
        inout headers_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t std_meta) {

    action forward(bit<9> port) {
        std_meta.egress_spec = port;
    }

    action drop() {
        mark_to_drop(std_meta);
    }

    table l2_forward {
        key = {
            hdr.ethernet.src_addr : exact;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
        size = 1024;
    }

    apply {
        l2_forward.apply();
    }
}

/* ---------- Egress (pass-through) ---------- */

control MyEgress(
        inout headers_t hdr,
        inout metadata_t meta,
        inout standard_metadata_t std_meta) {
    apply {}
}

/* ---------- Checksum update (none needed) ---------- */

control MyComputeChecksum(inout headers_t hdr, inout metadata_t meta) {
    apply {}
}

/* ---------- Deparser ---------- */

control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.vlan);
    }
}

/* ---------- Pipeline ---------- */

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
