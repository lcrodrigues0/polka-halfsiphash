/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "polka.p4h"

// A parser for general packets: it needs to be able to parse both incoming (ipv4) and outgoing (srcrouting) packets
parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        // Reads and pops the header. We will need to `.emit()` it back later
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            // If the packet comes from outside (ethernet packet)
            TYPE_IPV4: parse_ipv4;
            
            // If the packet comes inside (polka packet)
            TYPE_POLKA: parse_polka;
            
            // Any other packet
            default: accept;
        }
    }

    state parse_polka {
        packet.extract(hdr.polka);

        transition select(hdr.polka.version) {
            PROBE_VERSION: parse_polka_probe;
            // Any other packet
            default: parse_ipv4;
        }
    }

    state parse_polka_probe {
        packet.extract(hdr.polka_probe);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {
        // No checksum verification is done
    }
}

control MySeed(
    inout headers hdr,
    inout metadata meta
) {
    // Sets a configured seed for the timestamp
    action seed (
        bit<32> setseed
    ){
        hdr.polka_probe.setValid(); 
        hdr.polka_probe.timestamp = setseed;
    }

    // Adds a Polka header to the packet 
    // Table name can't be changed because it is the name defined by node configuration files
    table config {
        key = {
            meta.apply_sr: exact;
        }
        actions = {
            // Actions names also can't be changed because they are the names defined by node configuration files
            seed;
        }
        size = 128;
    }

    apply {
        meta.apply_sr = 0;
        config.apply();
    }
}

control TunnelEncap(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    action tdrop() {
        mark_to_drop(standard_metadata);
    }

    action add_sourcerouting_header (
        bit<9> port,
        bit<1> sr,
        mac_addr_t dmac,
        polka_route_t routeIdPacket
    ){
        // Has to be set to valid for changes to be commited
        hdr.polka.setValid();

        hdr.polka.version = REGULAR_VERSION;
        hdr.polka.ttl = 0xFF;
        
        meta.apply_sr = sr;
        standard_metadata.egress_spec = port;
        hdr.polka.routeid = routeIdPacket;
        hdr.ethernet.dst_mac_addr = dmac;

        hdr.polka.proto = TYPE_POLKA;
        // Replicating on both headers for consistency
        hdr.ethernet.ethertype = TYPE_POLKA;
    }


    // Adds a Polka header to the packet 
    // Table name can't be changed because it is the name defined by node configuration files
    table tunnel_encap_process_sr {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            // Actions names also can't be changed because they are the names defined by node configuration files
            add_sourcerouting_header;
            tdrop;
        }
        size = 1024;
        default_action = tdrop();
    }

    apply {
        tunnel_encap_process_sr.apply();

        if (meta.apply_sr == 0) {
            hdr.polka.setInvalid();
        // } else {
            // Not needed - it is already set to valid in inside match arm
        //     hdr.polka.setValid();
        }
    }
}

control MyProbe(
    inout headers hdr,
    inout metadata meta
) {
    action encap() {
        hdr.polka_probe.setValid();
        hdr.polka.version = PROBE_VERSION;
        // random(hdr.polka_probe.timestamp, 0, 0xFFFFFFFF);
        
        hdr.polka_probe.l_hash = hdr.polka_probe.timestamp;
    }

    apply {
        if (hdr.polka.version == PROBE_VERSION) {
            // Decap
            hdr.polka_probe.setInvalid();
        } else {
            // Generates a random number between 0 and 2^32 - 1
            // Set only 10% of packets to probe version
            // Currently set for 100% for debug
            // bit<4> is_probe = 3;
            // random(is_probe, 0, 10);
            // if (is_probe <= 10) { 
                MySeed.apply(hdr, meta);
                encap();
            // } else {
            //     hdr.polka.version = REGULAR_VERSION;
            //     hdr.polka_probe.setInvalid();
            // }
        }

    }
}

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // Removes extra headers from Polka packet, leaves it as if nothing had touched it.
    action tunnel_decap() {
        // Set ethertype to IPv4 since it is leaving Polka
        hdr.polka.proto = TYPE_IPV4;
        // Replicating on second header for consistency
        hdr.ethernet.ethertype = TYPE_IPV4;

        // Does not serialize routeid
        hdr.polka.setInvalid();

        // Should be enough to "decap" packet

        // In this example, port `1` is always the exit node
        standard_metadata.egress_spec = 1;
    }

    apply {
        if (hdr.ethernet.ethertype == TYPE_POLKA) {
            // Packet came from inside network, we need to make it a normal pkt
            tunnel_decap();
        } else {
            // Packet came from ouside network, we need to make it a polka pkt
            TunnelEncap.apply(hdr, meta, standard_metadata);
        }
        MyProbe.apply(hdr, meta);
    }
} 

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { 
        // Is actually also done on MyIngress
     }
}

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {
        // No checksum is calculated
    }
}

control MyDeparser(
    packet_out packet,
    in headers hdr
) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.polka);
        packet.emit(hdr.polka_probe);
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
