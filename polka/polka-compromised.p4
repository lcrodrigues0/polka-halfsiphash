/* -*- P4_16 -*- */
#include "polka-core-common.p4"

control CompromisedIngress(
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
        hash(
            nresult,
            HashAlgorithm.crc16_custom,
            nbase,
            {ndata},
            ncount
        );

        bit<16> nport = nresult ^ dif;

        // TODO probably doesn't need helper metadata field, acessing standard_metadata.egress_spec directly
        // IMPORTANT: Only change on this control is below
        // if incoming port is 1, then the egress port is 3, this is the attacker's port
        if (standard_metadata.ingress_port == 2) {
            meta.port = (bit<9>) 4;
        } else {
            meta.port = (bit<9>) nport;
        }
        
        standard_metadata.egress_spec = meta.port + 1;
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

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    CompromisedIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
