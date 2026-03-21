/*
 * l2_forward.p4 — L2 MAC forwarding for Tofino 2 (TNA)
 *
 * Simple exact-match on destination MAC address to forward frames
 * to a specific egress port.  The controller populates and updates
 * the "l2_forward" table at runtime via BF Runtime.
 */

#include <core.p4>
#include <tna.p4>

/* ---------- Headers ---------- */

header ethernet_h {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

struct headers_t {
    ethernet_h ethernet;
}

struct metadata_t {}

/* ---------- Ingress Parser ---------- */

parser IngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

/* ---------- Ingress ---------- */

control Ingress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in    ingress_intrinsic_metadata_t ig_intr_md,
        in    ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table l2_forward {
        key = {
            hdr.ethernet.dst_addr : exact;
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

/* ---------- Ingress Deparser ---------- */

control IngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in    metadata_t ig_md,
        in    ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

/* ---------- Egress Parser ---------- */

parser EgressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition accept;
    }
}

/* ---------- Egress (pass-through) ---------- */

control Egress(
        inout headers_t hdr,
        inout metadata_t eg_md,
        in    egress_intrinsic_metadata_t eg_intr_md,
        in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {

    apply {}
}

/* ---------- Egress Deparser ---------- */

control EgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in    metadata_t eg_md,
        in    egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {

    apply {
        pkt.emit(hdr);
    }
}

/* ---------- Pipeline ---------- */

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
