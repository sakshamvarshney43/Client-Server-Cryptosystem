/*
 * File    : whirlpool.h
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Whirlpool hash (final ISO/IEC 10118-3 version) written from scratch.
 *           512-bit digest, 512-bit blocks, 10 rounds, Miyaguchi-Preneel mode.
 *           The S-box is NOT copied from a table: it is built from three small
 *           4-bit boxes (E, E^-1, R) exactly as the Whirlpool specification does.
 */
#ifndef WHIRLPOOL_H
#define WHIRLPOOL_H

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include "util.h"

namespace whirlpool {

typedef util::Bytes Bytes;

/* ---------- GF(2^8) arithmetic, polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11D) ---------- */
inline uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t r = 0;
    while (b) {
        if (b & 1) r ^= a;
        bool carry = (a & 0x80) != 0;
        a <<= 1;
        if (carry) a ^= 0x1D;        // reduce modulo 0x11D
        b >>= 1;
    }
    return r;
}

/* ---------- all constant tables, built once on first use ---------- */
struct Tables {
    uint8_t sbox[256];
    uint8_t rc[10][8];               // round constants (only row 0 is non-zero)
    uint8_t circ[8];                 // first row of circulant matrix C

    Tables() {
        // 4-bit mini boxes from the specification
        static const uint8_t E[16] = {0x1,0xB,0x9,0xC,0xD,0x6,0xF,0x3,0xE,0x8,0x7,0x4,0xA,0x2,0x5,0x0};
        static const uint8_t R[16] = {0x7,0xC,0xB,0xD,0xE,0x4,0x9,0xF,0x6,0x3,0x8,0xA,0x2,0x5,0x1,0x0};
        uint8_t Einv[16];
        for (int i = 0; i < 16; i++) Einv[E[i]] = (uint8_t)i;

        // S-box: split byte into two nibbles, pass through E / Einv / R
        for (int u = 0; u < 256; u++) {
            uint8_t a = E[u >> 4];
            uint8_t b = Einv[u & 0x0F];
            uint8_t r = R[a ^ b];
            sbox[u] = (uint8_t)((E[a ^ r] << 4) | Einv[b ^ r]);
        }

        // round constants: round r (1..10) = first row is S[8(r-1)] ... S[8(r-1)+7]
        for (int r = 0; r < 10; r++)
            for (int j = 0; j < 8; j++) rc[r][j] = sbox[8 * r + j];

        static const uint8_t c[8] = {1, 1, 4, 1, 8, 5, 2, 9};
        for (int i = 0; i < 8; i++) circ[i] = c[i];
    }
};

inline const Tables &T() { static Tables t; return t; }

/* ---------- state = 8x8 bytes ---------- */
typedef uint8_t State[8][8];

// one round function rho[k]: gamma (S-box) -> pi (shift columns) -> theta (mix rows) -> sigma (xor key)
inline void round(State s, const State key) {
    const Tables &t = T();
    uint8_t g[8][8], p[8][8], m[8][8];

    // gamma: byte substitution
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) g[i][j] = t.sbox[s[i][j]];

    // pi: column j is cyclically shifted downwards by j positions
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) p[(i + j) & 7][j] = g[i][j];

    // theta: every row is multiplied by the circulant matrix C
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) {
            uint8_t v = 0;
            for (int k = 0; k < 8; k++)
                v ^= gmul(p[i][k], t.circ[(j - k) & 7]);
            m[i][j] = v;
        }

    // sigma: add (xor) the round key
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 8; j++) s[i][j] = m[i][j] ^ key[i][j];
}

// Compress one 64-byte block into the 64-byte chaining value h (Miyaguchi-Preneel)
inline void compress(uint8_t h[64], const uint8_t block[64]) {
    const Tables &t = T();
    State K, S, zeroKey;
    memset(zeroKey, 0, sizeof(zeroKey));

    for (int i = 0; i < 64; i++) {
        K[i / 8][i % 8] = h[i];                           // K0 = previous hash
        S[i / 8][i % 8] = block[i] ^ h[i];                // state = block xor K0
    }
    for (int r = 0; r < 10; r++) {
        State c;                                          // round constant matrix
        memset(c, 0, sizeof(c));
        for (int j = 0; j < 8; j++) c[0][j] = t.rc[r][j];
        round(K, c);                                      // next round key
        round(S, K);                                      // encrypt state with it
    }
    // h = E_h(block) xor h xor block
    for (int i = 0; i < 64; i++) h[i] ^= S[i / 8][i % 8] ^ block[i];
}

/* ---------- public API ---------- */

// Hash arbitrary bytes -> 64-byte digest
inline Bytes hash(const Bytes &msg) {
    uint8_t h[64];
    memset(h, 0, 64);

    // padding: bit '1', zeros up to 32 bytes short of a block boundary,
    // then 256-bit big-endian length of the message in bits
    Bytes p = msg;
    uint64_t bits = (uint64_t)msg.size() * 8;
    p.push_back(0x80);
    while (p.size() % 64 != 32) p.push_back(0x00);
    for (int i = 0; i < 24; i++) p.push_back(0x00);       // upper 192 bits of length
    for (int i = 7; i >= 0; i--) p.push_back((uint8_t)(bits >> (8 * i)));

    for (size_t off = 0; off < p.size(); off += 64) compress(h, &p[off]);
    return Bytes(h, h + 64);
}

inline std::string hashHex(const Bytes &msg) { return util::toHex(hash(msg)); }
inline std::string hashHex(const std::string &s) { return hashHex(util::strToBytes(s)); }

} // namespace whirlpool
#endif