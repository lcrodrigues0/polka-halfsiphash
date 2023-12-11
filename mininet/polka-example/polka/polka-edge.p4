/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "polka.p4h"

// A parser for general packets: it needs to be able to parse both incoming (ipv4) and outgoing (srcrouting) packets
parser MyParser(
    packet_in packet,
    out polka_t hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        // Reads and pops the header. We will need to `.emit()` it back later
        packet.extract(metadata.etherType);
        hdr.proto.etherType = metadata.etherType;
        transition select(metadata.etherType) {
            // If the packet comes from outside (ethernet packet)
            TYPE_IPV4: parse_ipv4;
            
            // If the packet comes inside (polka packet)
            TYPE_POLKA: parse_polka;
            
            // Any other packet
            default: accept;
        }
    }

    state parse_polka {
        packet.extract(hdr.routeid);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }


}

control MyVerifyChecksum(
    inout polka_t hdr,
    inout metadata meta
) {
    apply {
        // No checksum verification is done
    }
}

control TunnelEncap(
    inout polka_t hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    // Adds a Polka header to the packet 
    action add_sourcerouting_header (
        egressSpec_t port,
        bit<1> sr,
        macAddr_t dmac,
        bit<160>  routeIdPacket
    ){

        standard_metadata.egress_spec = port;
        meta.apply_sr = sr;

        hdr.proto.dstAddr = dmac;

        hdr.routeid.setValid();
        hdr.routeid.routeId = routeIdPacket;

    }

    // This needs to be name because it is the name defined by polka polynomes
    table tunnel_encap_process_sr {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            add_sourcerouting_header;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        tunnel_encap_process_sr.apply();
        if (meta.apply_sr!=1) {
            hdr.routeid.setInvalid();
        } else {
            hdr.proto.etherType = TYPE_POLKA;
        }

    }

}

control MyIngress(
    inout polka_t hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // Removes extra headers from Polka packet, leaves it as if nothing had touched it.
    action tunnel_decap() {
        // Set ethertype to IPv4 since it is leaving Polka
        hdr.proto.etherType = TYPE_IPV4;

        // Does not serialize routeid
        hdr.routeid.setInvalid();

        // Should be enough to "decap" packet

        // In this example, port `1` is always the exit node
        standard_metadata.egress_spec = 1;
    }
    
    apply {
        if (hdr.proto.etherType == TYPE_POLKA) {
            // Packet came from inside network
            tunnel_decap();
        } else if (hdr.ipv4.isValid()) {
            // Packet came from outside network
            TunnelEncap.apply(hdr, meta, standard_metadata);
        } 
    }
} 

control MyEgress(
    inout polka_t hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { 
        // Is actually also done on MyIngress
     }
}

control MyComputeChecksum(
    inout polka_t hdr,
    inout metadata meta
) {
    apply {
        // No checksum is calculated
    }
}

control MyDeparser(
    packet_out packet,
    in polka_t hdr
) {
    apply {
        packet.emit(hdr.proto);
        packet.emit(hdr.routeid);
        packet.emit(hdr.ipv4);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
