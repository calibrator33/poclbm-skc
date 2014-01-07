// OpenCL kernel to perform Skein hashes for SKC mining
//
// copyright 2013 reorder
//

#define ROL32(x, n)     rotate(x, (uint) n)
#define SHR(x, n)   ((x) >> n)
#define SWAP32(a)       (as_uint(as_uchar4(a).wzyx))

#define S0(x) (ROL32(x, 25) ^ ROL32(x, 14) ^  SHR(x, 3))
#define S1(x) (ROL32(x, 15) ^ ROL32(x, 13) ^  SHR(x, 10))

#define S2(x) (ROL32(x, 30) ^ ROL32(x, 19) ^ ROL32(x, 10))
#define S3(x) (ROL32(x, 26) ^ ROL32(x, 21) ^ ROL32(x, 7))

#define P(a,b,c,d,e,f,g,h,x,K)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + K + x;      \
    d += temp1; h = temp1 + S2(a) + F0(a,b,c);  \
}

#define PS(a,b,c,d,e,f,g,h,S)                  \
{                                               \
    temp1 = h + S3(e) + F1(e,f,g) + S;      \
    d += temp1; h = temp1 + S2(a) + F0(a,b,c);  \
}

#define PSLAST(a,b,c,d,e,f,g,h,S)                  \
{                                               \
    d += h + S3(e) + F1(e,f,g) + S;              \
}

#define F0(y, x, z) bitselect(z, y, z ^ x)
#define F1(x, y, z) bitselect(z, y, x)

#define R0 (W0 = S1(W14) + W9 + S0(W1) + W0)
#define R1 (W1 = S1(W15) + W10 + S0(W2) + W1)
#define R2 (W2 = S1(W0) + W11 + S0(W3) + W2)
#define R3 (W3 = S1(W1) + W12 + S0(W4) + W3)
#define R4 (W4 = S1(W2) + W13 + S0(W5) + W4)
#define R5 (W5 = S1(W3) + W14 + S0(W6) + W5)
#define R6 (W6 = S1(W4) + W15 + S0(W7) + W6)
#define R7 (W7 = S1(W5) + W0 + S0(W8) + W7)
#define R8 (W8 = S1(W6) + W1 + S0(W9) + W8)
#define R9 (W9 = S1(W7) + W2 + S0(W10) + W9)
#define R10 (W10 = S1(W8) + W3 + S0(W11) + W10)
#define R11 (W11 = S1(W9) + W4 + S0(W12) + W11)
#define R12 (W12 = S1(W10) + W5 + S0(W13) + W12)
#define R13 (W13 = S1(W11) + W6 + S0(W14) + W13)
#define R14 (W14 = S1(W12) + W7 + S0(W15) + W14)
#define R15 (W15 = S1(W13) + W8 + S0(W0) + W15)

#define RD14 (S1(W12) + W7 + S0(W15) + W14)
#define RD15 (S1(W13) + W8 + S0(W0) + W15)

inline uint sha256_res(uint16 data)
{
    uint temp1;
    uint W0 = SWAP32(data.s0);
    uint W1 = SWAP32(data.s1);
    uint W2 = SWAP32(data.s2);
    uint W3 = SWAP32(data.s3);
    uint W4 = SWAP32(data.s4);
    uint W5 = SWAP32(data.s5);
    uint W6 = SWAP32(data.s6);
    uint W7 = SWAP32(data.s7);
    uint W8 = SWAP32(data.s8);
    uint W9 = SWAP32(data.s9);
    uint W10 = SWAP32(data.sA);
    uint W11 = SWAP32(data.sB);
    uint W12 = SWAP32(data.sC);
    uint W13 = SWAP32(data.sD);
    uint W14 = SWAP32(data.sE);
    uint W15 = SWAP32(data.sF);

    uint v0 = 0x6A09E667U;
    uint v1 = 0xBB67AE85U;
    uint v2 = 0x3C6EF372U;
    uint v3 = 0xA54FF53AU;
    uint v4 = 0x510E527FU;
    uint v5 = 0x9B05688CU;
    uint v6 = 0x1F83D9ABU;
    uint v7 = 0x5BE0CD19U;

    P( v0, v1, v2, v3, v4, v5, v6, v7, W0, 0x428A2F98 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, W1, 0x71374491 );
    P( v6, v7, v0, v1, v2, v3, v4, v5, W2, 0xB5C0FBCF );
    P( v5, v6, v7, v0, v1, v2, v3, v4, W3, 0xE9B5DBA5 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, W4, 0x3956C25B );
    P( v3, v4, v5, v6, v7, v0, v1, v2, W5, 0x59F111F1 );
    P( v2, v3, v4, v5, v6, v7, v0, v1, W6, 0x923F82A4 );
    P( v1, v2, v3, v4, v5, v6, v7, v0, W7, 0xAB1C5ED5 );
    P( v0, v1, v2, v3, v4, v5, v6, v7, W8, 0xD807AA98 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, W9, 0x12835B01 );
    P( v6, v7, v0, v1, v2, v3, v4, v5, W10, 0x243185BE );
    P( v5, v6, v7, v0, v1, v2, v3, v4, W11, 0x550C7DC3 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, W12, 0x72BE5D74 );
    P( v3, v4, v5, v6, v7, v0, v1, v2, W13, 0x80DEB1FE );
    P( v2, v3, v4, v5, v6, v7, v0, v1, W14, 0x9BDC06A7 );
    P( v1, v2, v3, v4, v5, v6, v7, v0, W15, 0xC19BF174 );

    P( v0, v1, v2, v3, v4, v5, v6, v7, R0, 0xE49B69C1 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, R1, 0xEFBE4786 );
    P( v6, v7, v0, v1, v2, v3, v4, v5, R2, 0x0FC19DC6 );
    P( v5, v6, v7, v0, v1, v2, v3, v4, R3, 0x240CA1CC );
    P( v4, v5, v6, v7, v0, v1, v2, v3, R4, 0x2DE92C6F );
    P( v3, v4, v5, v6, v7, v0, v1, v2, R5, 0x4A7484AA );
    P( v2, v3, v4, v5, v6, v7, v0, v1, R6, 0x5CB0A9DC );
    P( v1, v2, v3, v4, v5, v6, v7, v0, R7, 0x76F988DA );
    P( v0, v1, v2, v3, v4, v5, v6, v7, R8, 0x983E5152 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, R9, 0xA831C66D );
    P( v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xB00327C8 );
    P( v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xBF597FC7 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xC6E00BF3 );
    P( v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD5A79147 );
    P( v2, v3, v4, v5, v6, v7, v0, v1, R14, 0x06CA6351 );
    P( v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x14292967 );

    P( v0, v1, v2, v3, v4, v5, v6, v7, R0,  0x27B70A85 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, R1,  0x2E1B2138 );
    P( v6, v7, v0, v1, v2, v3, v4, v5, R2,  0x4D2C6DFC );
    P( v5, v6, v7, v0, v1, v2, v3, v4, R3,  0x53380D13 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, R4,  0x650A7354 );
    P( v3, v4, v5, v6, v7, v0, v1, v2, R5,  0x766A0ABB );
    P( v2, v3, v4, v5, v6, v7, v0, v1, R6,  0x81C2C92E );
    P( v1, v2, v3, v4, v5, v6, v7, v0, R7,  0x92722C85 );
    P( v0, v1, v2, v3, v4, v5, v6, v7, R8,  0xA2BFE8A1 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, R9,  0xA81A664B );
    P( v6, v7, v0, v1, v2, v3, v4, v5, R10, 0xC24B8B70 );
    P( v5, v6, v7, v0, v1, v2, v3, v4, R11, 0xC76C51A3 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, R12, 0xD192E819 );
    P( v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xD6990624 );
    P( v2, v3, v4, v5, v6, v7, v0, v1, R14, 0xF40E3585 );
    P( v1, v2, v3, v4, v5, v6, v7, v0, R15, 0x106AA070 );

    P( v0, v1, v2, v3, v4, v5, v6, v7, R0,  0x19A4C116 );
    P( v7, v0, v1, v2, v3, v4, v5, v6, R1,  0x1E376C08 );
    P( v6, v7, v0, v1, v2, v3, v4, v5, R2,  0x2748774C );
    P( v5, v6, v7, v0, v1, v2, v3, v4, R3,  0x34B0BCB5 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, R4,  0x391C0CB3 );
    P( v3, v4, v5, v6, v7, v0, v1, v2, R5,  0x4ED8AA4A );
    P( v2, v3, v4, v5, v6, v7, v0, v1, R6,  0x5B9CCA4F );
    P( v1, v2, v3, v4, v5, v6, v7, v0, R7,  0x682E6FF3 );
    P( v0, v1, v2, v3, v4, v5, v6, v7, R8,  0x748F82EE );
    P( v7, v0, v1, v2, v3, v4, v5, v6, R9,  0x78A5636F );
    P( v6, v7, v0, v1, v2, v3, v4, v5, R10, 0x84C87814 );
    P( v5, v6, v7, v0, v1, v2, v3, v4, R11, 0x8CC70208 );
    P( v4, v5, v6, v7, v0, v1, v2, v3, R12, 0x90BEFFFA );
    P( v3, v4, v5, v6, v7, v0, v1, v2, R13, 0xA4506CEB );
    P( v2, v3, v4, v5, v6, v7, v0, v1, RD14, 0xBEF9A3F7 );
    P( v1, v2, v3, v4, v5, v6, v7, v0, RD15, 0xC67178F2 );

    v0 += 0x6A09E667U;
    v1 += 0xBB67AE85U;
    v2 += 0x3C6EF372U;
    v3 += 0xA54FF53AU;
    v4 += 0x510E527FU;
    v5 += 0x9B05688CU;
    v6 += 0x1F83D9ABU;
    v7 += 0x5BE0CD19U;
    uint s7 = v7;

    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x80000000 + 0x428A2F98 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0 + 0x71374491 );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0 + 0xB5C0FBCF );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0 + 0xE9B5DBA5 );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0 + 0x3956C25B );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0 + 0x59F111F1 );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0 + 0x923F82A4 );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 0 + 0xAB1C5ED5 );
    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0 + 0xD807AA98 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0 + 0x12835B01 );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0 + 0x243185BE );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0 + 0x550C7DC3 );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0 + 0x72BE5D74 );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0 + 0x80DEB1FE );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0 + 0x9BDC06A7 );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 512 + 0xC19BF174 );

    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x80000000 + 0xE49B69C1 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0x01400000 + 0xEFBE4786 );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0x00205000 + 0x0FC19DC6 );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0x00005088 + 0x240CA1CC );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0x22000800 + 0x2DE92C6F );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0x22550014 + 0x4A7484AA );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0x05089742 + 0x5CB0A9DC );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 0xa0000020 + 0x76F988DA );
    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x5a880000 + 0x983E5152 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0x005c9400 + 0xA831C66D );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0x0016d49d + 0xB00327C8 );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0xfa801f00 + 0xBF597FC7 );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0xd33225d0 + 0xC6E00BF3 );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0x11675959 + 0xD5A79147 );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0xf6e6bfda + 0x06CA6351 );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 0xb30c1549 + 0x14292967 );
    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x08b2b050 + 0x27B70A85 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0x9d7c4c27 + 0x2E1B2138 );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0x0ce2a393 + 0x4D2C6DFC );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0x88e6e1ea + 0x53380D13 );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0xa52b4335 + 0x650A7354 );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0x67a16f49 + 0x766A0ABB );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0xd732016f + 0x81C2C92E );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 0x4eeb2e91 + 0x92722C85 );
    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x5dbf55e5 + 0xA2BFE8A1 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0x8eee2335 + 0xA81A664B );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0xe2bc5ec2 + 0xC24B8B70 );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0xa83f4394 + 0xC76C51A3 );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0x45ad78f7 + 0xD192E819 );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0x36f3d0cd + 0xD6990624 );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0xd99c05e8 + 0xF40E3585 );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 0xb0511dc7 + 0x106AA070 );
    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x69bc7ac4 + 0x19A4C116 );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0xbd11375b + 0x1E376C08 );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0xe3ba71e5 + 0x2748774C );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0x3b209ff2 + 0x34B0BCB5 );
    PS( v4, v5, v6, v7, v0, v1, v2, v3, 0x18feee17 + 0x391C0CB3 );
    PS( v3, v4, v5, v6, v7, v0, v1, v2, 0xe25ad9e7 + 0x4ED8AA4A );
    PS( v2, v3, v4, v5, v6, v7, v0, v1, 0x13375046 + 0x5B9CCA4F );
    PS( v1, v2, v3, v4, v5, v6, v7, v0, 0x0515089d + 0x682E6FF3 );
    PS( v0, v1, v2, v3, v4, v5, v6, v7, 0x4f0d0f04 + 0x748F82EE );
    PS( v7, v0, v1, v2, v3, v4, v5, v6, 0x2627484e + 0x78A5636F );
    PS( v6, v7, v0, v1, v2, v3, v4, v5, 0x310128d2 + 0x84C87814 );
    PS( v5, v6, v7, v0, v1, v2, v3, v4, 0xc668b434 + 0x8CC70208 );
    PSLAST( v4, v5, v6, v7, v0, v1, v2, v3, 0x420841cc + 0x90BEFFFA );

    return v7 + s7;
}

#if 1
#define rolhackl(n) \
inline ulong rol ## n  (ulong l) \
{ \
    uint2 t = rotate(as_uint2(l), (n)); \
    return as_ulong((uint2)(bitselect(t.s0, t.s1, (uint)(1 << (n)) - 1), bitselect(t.s0, t.s1, (uint)(~((1 << (n)) - 1))))); \
}

rolhackl(8)
rolhackl(9)
rolhackl(10)
rolhackl(13)
rolhackl(14)
rolhackl(17)
rolhackl(19)
rolhackl(22)
rolhackl(24)
rolhackl(25)
rolhackl(27)
rolhackl(29)
rolhackl(30)

#define rolhackr(n) \
inline ulong rol ## n  (ulong l) \
{ \
    uint2 t = rotate(as_uint2(l), (n - 32)); \
    return as_ulong((uint2)(bitselect(t.s1, t.s0, (uint)(1 << (n - 32)) - 1), bitselect(t.s1, t.s0, (uint)(~((1 << (n - 32)) - 1))))); \
}

rolhackr(33)
rolhackr(34)
rolhackr(35)
rolhackr(36)
rolhackr(37)
rolhackr(39)
rolhackr(42)
rolhackr(43)
rolhackr(44)
rolhackr(46)
rolhackr(49)
rolhackr(50)
rolhackr(54)
rolhackr(56)
#else
#define rol8(l) rotate(l, 8UL)
#define rol9(l) rotate(l, 9UL)
#define rol10(l) rotate(l, 10UL)
#define rol13(l) rotate(l, 13UL)
#define rol14(l) rotate(l, 14UL)
#define rol17(l) rotate(l, 17UL)
#define rol19(l) rotate(l, 19UL)
#define rol22(l) rotate(l, 22UL)
#define rol24(l) rotate(l, 24UL)
#define rol25(l) rotate(l, 25UL)
#define rol27(l) rotate(l, 27UL)
#define rol29(l) rotate(l, 29UL)
#define rol30(l) rotate(l, 30UL)
#define rol33(l) rotate(l, 33UL)
#define rol34(l) rotate(l, 34UL)
#define rol35(l) rotate(l, 35UL)
#define rol36(l) rotate(l, 36UL)
#define rol37(l) rotate(l, 37UL)
#define rol39(l) rotate(l, 39UL)
#define rol42(l) rotate(l, 42UL)
#define rol43(l) rotate(l, 43UL)
#define rol44(l) rotate(l, 44UL)
#define rol46(l) rotate(l, 46UL)
#define rol49(l) rotate(l, 49UL)
#define rol50(l) rotate(l, 50UL)
#define rol54(l) rotate(l, 54UL)
#define rol56(l) rotate(l, 56UL)
#endif

#define SKEIN_ROL_0_0(x) rol46(x)
#define SKEIN_ROL_0_1(x) rol36(x) 
#define SKEIN_ROL_0_2(x) rol19(x) 
#define SKEIN_ROL_0_3(x) rol37(x) 
#define SKEIN_ROL_1_0(x) rol33(x) 
#define SKEIN_ROL_1_1(x) rol27(x) 
#define SKEIN_ROL_1_2(x) rol14(x) 
#define SKEIN_ROL_1_3(x) rol42(x) 
#define SKEIN_ROL_2_0(x) rol17(x) 
#define SKEIN_ROL_2_1(x) rol49(x) 
#define SKEIN_ROL_2_2(x) rol36(x) 
#define SKEIN_ROL_2_3(x) rol39(x) 
#define SKEIN_ROL_3_0(x) rol44(x) 
#define SKEIN_ROL_3_1(x) rol9(x) 
#define SKEIN_ROL_3_2(x) rol54(x) 
#define SKEIN_ROL_3_3(x) rol56(x) 
#define SKEIN_ROL_4_0(x) rol39(x) 
#define SKEIN_ROL_4_1(x) rol30(x) 
#define SKEIN_ROL_4_2(x) rol34(x) 
#define SKEIN_ROL_4_3(x) rol24(x) 
#define SKEIN_ROL_5_0(x) rol13(x) 
#define SKEIN_ROL_5_1(x) rol50(x) 
#define SKEIN_ROL_5_2(x) rol10(x) 
#define SKEIN_ROL_5_3(x) rol17(x) 
#define SKEIN_ROL_6_0(x) rol25(x) 
#define SKEIN_ROL_6_1(x) rol29(x) 
#define SKEIN_ROL_6_2(x) rol39(x) 
#define SKEIN_ROL_6_3(x) rol43(x) 
#define SKEIN_ROL_7_0(x) rol8(x) 
#define SKEIN_ROL_7_1(x) rol35(x) 
#define SKEIN_ROL_7_2(x) rol56(x) 
#define SKEIN_ROL_7_3(x) rol22(x) 

#define SKEIN_KS_PARITY         0x1BD11BDAA9FC1A22UL

#define SKEIN_R512(p0,p1,p2,p3,p4,p5,p6,p7,ROTS)                      \
    X.s##p0 += X.s##p1; \
    X.s##p2 += X.s##p3; \
    X.s##p4 += X.s##p5; \
    X.s##p6 += X.s##p7; \
    X.s##p1 = SKEIN_ROL_ ## ROTS ## _0(X.s##p1) ^ X.s##p0; \
    X.s##p3 = SKEIN_ROL_ ## ROTS ## _1(X.s##p3) ^ X.s##p2; \
    X.s##p5 = SKEIN_ROL_ ## ROTS ## _2(X.s##p5) ^ X.s##p4; \
    X.s##p7 = SKEIN_ROL_ ## ROTS ## _3(X.s##p7) ^ X.s##p6;

#define SKEIN_I512(R)                                                     \
    X.s0   += ks[((R)+1) % 9];   /* inject the key schedule value */  \
    X.s1   += ks[((R)+2) % 9];                                        \
    X.s2   += ks[((R)+3) % 9];                                        \
    X.s3   += ks[((R)+4) % 9];                                        \
    X.s4   += ks[((R)+5) % 9];                                        \
    X.s5   += ks[((R)+6) % 9] + ts[((R)+1) % 3];                      \
    X.s6   += ks[((R)+7) % 9] + ts[((R)+2) % 3];                      \
    X.s7   += ks[((R)+8) % 9] +     (R)+1;                            \

#define SKEIN_R512_8_rounds(R) \
        SKEIN_R512(0,1,2,3,4,5,6,7, 0);   \
        SKEIN_R512(2,1,4,7,6,5,0,3, 1);   \
        SKEIN_R512(4,1,6,3,0,5,2,7, 2);   \
        SKEIN_R512(6,1,0,7,2,5,4,3, 3);   \
        SKEIN_I512(2*(R));                              \
        SKEIN_R512(0,1,2,3,4,5,6,7, 4);   \
        SKEIN_R512(2,1,4,7,6,5,0,3, 5);   \
        SKEIN_R512(4,1,6,3,0,5,2,7, 6);   \
        SKEIN_R512(6,1,0,7,2,5,4,3, 7);   \
        SKEIN_I512(2*(R)+1);

inline ulong8 skein512_mid_impl(ulong8 X, ulong2 msg)
{
    ulong ts[3], ks[9];

    vstore8(X, 0, ks);
    X.s01 += msg;

    ks[8] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^
            ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^ SKEIN_KS_PARITY;

    ts[0] = 80;
    ts[1] = 176UL << 56;
    ts[2] = 0xB000000000000050UL;

    X.s5 += 80;
    X.s6 += 176UL << 56;

    SKEIN_R512_8_rounds( 0);
    SKEIN_R512_8_rounds( 1);
    SKEIN_R512_8_rounds( 2);
    SKEIN_R512_8_rounds( 3);
    SKEIN_R512_8_rounds( 4);
    SKEIN_R512_8_rounds( 5);
    SKEIN_R512_8_rounds( 6);
    SKEIN_R512_8_rounds( 7);
    SKEIN_R512_8_rounds( 8);

    X.s01 ^= msg;
    vstore8(X, 0, ks);

    ks[8] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^
            ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^ SKEIN_KS_PARITY;

    ts[0] = 8UL;
    ts[1] = 255UL << 56;
    ts[2] = 0xFF00000000000008UL;

    X.s5 += 8UL;
    X.s6 += 255UL << 56;

    SKEIN_R512_8_rounds( 0);
    SKEIN_R512_8_rounds( 1);
    SKEIN_R512_8_rounds( 2);
    SKEIN_R512_8_rounds( 3);
    SKEIN_R512_8_rounds( 4);
    SKEIN_R512_8_rounds( 5);
    SKEIN_R512_8_rounds( 6);
    SKEIN_R512_8_rounds( 7);
    SKEIN_R512_8_rounds( 8);

    return X;
}

__kernel void search(const ulong state0, const ulong state1, const ulong state2, const ulong state3,
                     const ulong state4, const ulong state5, const ulong state6, const ulong state7,
                     const uint data16, const uint data17, const uint data18,
                     const uint base,
                     __global uint* output)
{
    local uint nonce;
    nonce = base + get_global_id(0);
    ulong8 state = (ulong8)(state0, state1, state2, state3, state4, state5, state6, state7);

    ulong2 msg = as_ulong2((uint4)(data16, data17, data18, SWAP32(nonce)));

    if(sha256_res(as_uint16(skein512_mid_impl(state, msg))) & 0xf0ffffff)
        return;
    output[OUTPUT_SIZE] = output[nonce & OUTPUT_MASK] = nonce;
}
