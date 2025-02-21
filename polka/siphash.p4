struct _state {
    bit<32> v0;
    bit<32> v1;
    bit<32> v2;
    bit<32> v3;
}


control HalfSipHash_2_4_32(
    in bit<64> key,
    inout bit<32> data
) {
    action rotate_left(inout bit<32> x, in bit<8> n) {
        x = (x << n) | (x >> (32 - n));
    }
    action sipRound(inout _state s) {
        s.v0 = s.v0 + s.v1;
        rotate_left(s.v1, 5);
        s.v1 = s.v1 ^ s.v0;
        rotate_left(s.v0, 16);
        s.v2 = s.v2 + s.v3;
        rotate_left(s.v3, 8);
        s.v3 = s.v3 ^ s.v2;
        s.v0 = s.v0 + s.v3;
        rotate_left(s.v3, 7);
        s.v3 = s.v3 ^ s.v0;
        s.v2 = s.v2 + s.v1;
        rotate_left(s.v1, 13);
        s.v1 = s.v1 ^ s.v2;
        rotate_left(s.v2, 16);
    }

    action flip_endianness(out bit<32> p, in bit<32> v) {
        p[7:0] = v[31:24];
        p[15:8] = v[23:16];
        p[23:16] = v[15:8];
        p[31:24] = v[7:0];
    }

    // Compression is trivial since we are only hashing a single 32b word
    action compression(){}

    apply {
        bit<32> k0 = key[63:56] ++ key[55:48] ++ key[47:40] ++ key[39:32];
        bit<32> k1 = key[31:24] ++ key[23:16] ++ key[15:8] ++ key[7:0];
        bit<32> b = 0x04000000;

        _state s;
        s.v0 = k0 ^ 0x00000000;
        s.v1 = k1 ^ 0x00000000;
        s.v2 = k0 ^ 0x6c796765;
        s.v3 = k1 ^ 0x74656462;

        bit<32> m;
        compression();
        flip_endianness(m, data);

        // Ingesting
        s.v3 = s.v3 ^ m;
        sipRound(s);
        sipRound(s);
        s.v0 = s.v0 ^ m;

        // Wrapping up
        s.v3 = s.v3 ^ b;

        sipRound(s);
        sipRound(s);
        s.v0 = s.v0 ^ b; 
        s.v2 = s.v2 ^ 0x000000ff;

        sipRound(s);
        sipRound(s);
        sipRound(s);
        sipRound(s);

        flip_endianness(data, s.v1 ^ s.v3);

    }
}
