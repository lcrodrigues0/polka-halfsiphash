/* -*- P4_16 -*- */
#include "polka-core-common.p4"

// Replicates the regular signPacket control, but tried to guess a switchId
control AttackerSignPacket(
    inout headers hdr,
    inout metadata meta
) {
    // Signs the packet
    apply {
        // Gets the routeId and installs it on meta.route_id
        meta.switch_id = 0x1337;
        hdr.polka_probe.setValid();

        // At this point, `meta.port` should be written on already
        hdr.polka_probe.l_hash = (bit<32>) meta.port ^ hdr.polka_probe.l_hash ^ (bit<32>) meta.switch_id;

        bit<16> nbase = 0;
        bit<32> min_bound = 0;
        bit<32> max_bound = 0xFFFFFFFF;
        hash(
            hdr.polka_probe.l_hash,
            HashAlgorithm.crc32,
            min_bound,
            {hdr.polka_probe.l_hash},
            max_bound
        );
    }
}

control AttackerIngress(
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
        meta.port = (bit<9>) nport;
        standard_metadata.egress_spec = meta.port;
    }

    apply {
        if (meta.apply_sr == 0) {
            mark_to_drop(standard_metadata);
        } else {
            // srcRoute_nhop();
            if (standard_metadata.ingress_port == 0) {
                standard_metadata.egress_spec = 1;
            } else {
                standard_metadata.egress_spec = 0;
            }
            if (hdr.polka.version == PROBE_VERSION) {
                // IMPORTANT: Only change is here for this control
                AttackerSignPacket.apply(hdr, meta); 
            } else {
                hdr.polka_probe.setInvalid();
            }
        }
    }
}


V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    AttackerIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
