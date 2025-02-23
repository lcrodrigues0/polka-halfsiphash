/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#include "polka.p4h"
#include "siphash.p4"

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    state start {
        meta.apply_sr = 0;
        transition verify_ethernet;
    }

    state verify_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype) {
            TYPE_POLKA: get_polka_header;
            // Should be dropped when apply_sr is 0
            // But can't use drop here on BMV2
            default: accept;
        }
    }

    state get_polka_header {
        meta.apply_sr = 1;
        packet.extract(hdr.polka);
        meta.route_id = hdr.polka.routeid;

        transition select(hdr.polka.version) {
            PROBE_VERSION: parse_polka_probe;
            // Any other packet
            default: accept;
        }
    }

    state parse_polka_probe {
        packet.extract(hdr.polka_probe);
        transition accept;
    }

}

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {  }
}

control MySwitchId(
    inout headers hdr,
    inout metadata meta
) {
    action switchid (
        bit<16> switch_id
    ){
       meta.switch_id = switch_id;
    }

    // Adds a Polka header to the packet 
    // Table name can't be changed because it is the name defined by node configuration files
    table config {
        key = {
            meta.apply_sr: exact;
        }
        actions = {
            // Actions names also can't be changed because they are the names defined by node configuration files
            switchid;
        }
        size = 128;
    }

    apply {
        meta.apply_sr = 0;
        config.apply();
        hdr.polka.ttl = meta.switch_id[7:0];
    }
}

control MySignPacket(
    inout headers hdr,
    inout metadata meta
) {
    // Signs the packet
    apply {
        // Gets the routeId and installs it on meta.route_id
        MySwitchId.apply(hdr, meta);
        hdr.polka_probe.setValid();

        HalfSipHash_2_4_32.apply(
            meta.switch_id ++ meta.port ++ hdr.polka_probe.timestamp ++ 7w0,
            hdr.polka_probe.l_hash
        );
    }
}

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    // Calculates the next hop (port) based on the routeid (inside the crc16 custom hash result)
    action srcRoute_nhop() {
        // routeId % switchId = portId
        
        bit<160> ndata = meta.route_id >> 16;
        bit<16> dif = (bit<16>) (meta.route_id ^ (ndata << 16));

        bit<16> nresult;
        bit<64> ncount = 4294967296 * 2;
        bit<16> nbase = 0;
        // https://github.com/p4lang/p4c/blob/f44f4459b71b78b752977cd952b266fcb1e77943/p4include/v1model.p4#L428-L444
        hash(
            nresult,
            HashAlgorithm.crc16_custom,
            nbase,
            {ndata},
            ncount
        );

        bit<16> nport = nresult ^ dif;

        // TODO probably doesn't need helper metadata field, acessing standard_metadata.egress_spec directly
        meta.port = (bit<9>) nport;
        standard_metadata.egress_spec = meta.port;
    }

    apply {
        if (meta.apply_sr == 0) {
            mark_to_drop(standard_metadata);
        } else {
            srcRoute_nhop();
            standard_metadata.egress_spec = meta.port;
            if (hdr.polka.version == PROBE_VERSION) {
                MySignPacket.apply(hdr, meta);
            } else {
                hdr.polka_probe.setInvalid();
            }
        }
    }
}

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {
    apply { 
        // Packet isn't leaving the core
     }
}

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {
    apply {
        // No checksum currently being calculated
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
