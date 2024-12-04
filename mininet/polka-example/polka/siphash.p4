struct sstate {
    bit<32> v0;
    bit<32> v1;
    bit<32> v2;
    bit<32> v3;
}


control HalfSipHash_2_4_32(
    in bit<64> key,
    inout bit<32> data
) {
    action sipRound(inout sstate s) {
        s.v0 = s.v0 + s.v1;
        s.v1 = s.v1 << 5;
        s.v1 = s.v1 ^ s.v0;
        s.v0 = s.v0 << 16;
        s.v2 = s.v2 + s.v3;
        s.v3 = s.v3 << 8;
        s.v3 = s.v3 ^ s.v2;
        s.v0 = s.v0 + s.v3;
        s.v3 = s.v3 << 7;
        s.v3 = s.v3 ^ s.v0;
        s.v2 = s.v2 + s.v1;
        s.v1 = s.v1 << 13;
        s.v1 = s.v1 ^ s.v2;
        s.v2 = s.v2 << 16;
    }

    // TODO: Compression
    action compression(){}

    apply {
        bit<32> k0 = key[31:0];
        bit<32> k1 = key[63:32];

        sstate s;
        s.v0 = k0 ^ 0x00000000;
        s.v1 = k1 ^ 0x00000000;
        s.v2 = k0 ^ 0x6c796765;
        s.v3 = k1 ^ 0x74656462;

        compression();

        bit<32> m;

        m = data[31:0];
        s.v3 = s.v3 ^ m;
        sipRound(s);
        sipRound(s);
        s.v0 = s.v0 ^ m;

        s.v2 = s.v2 ^ 0x000000ff;
        sipRound(s);
        sipRound(s);
        sipRound(s);
        sipRound(s);

        data = s.v0 ^ s.v1 ^ s.v2 ^ s.v3;
    }
}
