/*
 * File    : idea.h
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Simplified IDEA (Nick Hoffman) - symmetric cipher, written from scratch.
 *           Block = 16 bits (4 nibbles), Key = 32 bits,
 *           4 full rounds + 1 half round, 28 sub-keys of 4 bits.
 *           Basic operations on nibbles:
 *             XOR, addition mod 16, multiplication mod 17 (nibble 0 means 16).
 *           Messages are encrypted block by block (ECB) with padding.
 */
#ifndef IDEA_H
#define IDEA_H

#include <iostream>
#include <vector>
#include <cstdint>
#include "util.h"

namespace idea {

typedef std::vector<uint8_t> Keys;   // each element is one 4-bit sub-key

/* ---------------- basic operations on nibbles ---------------- */

// addition modulo 2^4 = 16
inline uint8_t add(uint8_t a, uint8_t b) { return (a + b) & 0x0F; }

// multiplication modulo 2^4 + 1 = 17; nibble 0000 stands for 16
inline uint8_t mul(uint8_t a, uint8_t b) {
    int x = (a == 0) ? 16 : a;
    int y = (b == 0) ? 16 : b;
    int r = (x * y) % 17;
    return (uint8_t)(r == 16 ? 0 : r);   // 16 is stored back as 0000
}

// additive inverse modulo 16
inline uint8_t addInv(uint8_t a) { return (16 - a) & 0x0F; }

// multiplicative inverse modulo 17 (brute force; 0000 (=16) is its own inverse)
inline uint8_t mulInv(uint8_t a) {
    for (int i = 0; i < 16; i++)
        if (mul(a, (uint8_t)i) == 1) return (uint8_t)i;
    return 0;
}

/* ---------------- key schedule ---------------- */

// 32-bit key -> 28 encryption sub-keys.
// Take the 8 nibbles of the key, then rotate the key left by 6 bits,
// take 8 nibbles again, ... until 28 nibbles are collected.
inline Keys expandKey(uint32_t key) {
    Keys z;
    while (z.size() < 28) {
        for (int i = 0; i < 8 && z.size() < 28; i++)
            z.push_back((key >> (28 - 4 * i)) & 0x0F);   // leftmost nibble first
        key = (key << 6) | (key >> 26);                   // cyclic left shift by 6
    }
    return z;
}

// Encryption sub-keys -> decryption sub-keys (as in the Part 1 table):
//   K1, K4 = multiplicative inverse of Z1, Z4
//   K2, K3 = additive inverse of Z2, Z3
//   K5, K6 = Z5, Z6 of the previous encryption round
inline Keys decryptionKeys(const Keys &z) {
    Keys k(28);
    for (int r = 0; r < 4; r++) {
        int src = 24 - 6 * r;          // encryption round (5 - r) is used for K1..K4
        int dst = 6 * r;
        k[dst + 0] = mulInv(z[src + 0]);
        k[dst + 1] = addInv(z[src + 1]);
        k[dst + 2] = addInv(z[src + 2]);
        k[dst + 3] = mulInv(z[src + 3]);
        k[dst + 4] = z[src - 2];       // K5, K6 come from the round before
        k[dst + 5] = z[src - 1];
    }
    // half round uses the inverses of the first round's keys
    k[24] = mulInv(z[0]);
    k[25] = addInv(z[1]);
    k[26] = addInv(z[2]);
    k[27] = mulInv(z[3]);
    return k;
}

/* ---------------- one block (16 bits) ---------------- */

// Encrypts OR decrypts one block - only the key list differs.
// roundOut (optional) receives the block after each of the 5 rounds.
inline uint16_t cryptBlock(uint16_t in, const Keys &k, std::vector<uint16_t> *roundOut = 0) {
    uint8_t x1 = (in >> 12) & 0xF, x2 = (in >> 8) & 0xF,
            x3 = (in >> 4) & 0xF,  x4 = in & 0xF;

    for (int r = 0; r < 4; r++) {                 // 4 full rounds
        const uint8_t *z = &k[6 * r];
        uint8_t s1  = mul(x1, z[0]);              // step 1
        uint8_t s2  = add(x2, z[1]);              // step 2
        uint8_t s3  = add(x3, z[2]);              // step 3
        uint8_t s4  = mul(x4, z[3]);              // step 4
        uint8_t s5  = s1 ^ s3;                    // step 5
        uint8_t s6  = s2 ^ s4;                    // step 6
        uint8_t s7  = mul(s5, z[4]);              // step 7
        uint8_t s8  = add(s6, s7);                // step 8
        uint8_t s9  = mul(s8, z[5]);              // step 9
        uint8_t s10 = add(s7, s9);                // step 10
        uint8_t s11 = s1 ^ s9;                    // step 11
        uint8_t s12 = s3 ^ s9;                    // step 12
        uint8_t s13 = s2 ^ s10;                   // step 13
        uint8_t s14 = s4 ^ s10;                   // step 14
        // output of the round = step11 || step13 || step12 || step14 (middle swap)
        x1 = s11; x2 = s13; x3 = s12; x4 = s14;
        if (roundOut)
            roundOut->push_back((uint16_t)((x1 << 12) | (x2 << 8) | (x3 << 4) | x4));
    }

    // half round (round 5): no swap afterwards
    const uint8_t *z = &k[24];
    uint8_t y1 = mul(x1, z[0]);
    uint8_t y2 = add(x2, z[1]);
    uint8_t y3 = add(x3, z[2]);
    uint8_t y4 = mul(x4, z[3]);
    uint16_t out = (uint16_t)((y1 << 12) | (y2 << 8) | (y3 << 4) | y4);
    if (roundOut) roundOut->push_back(out);
    return out;
}

/* ---------------- whole messages ---------------- */

// prints sub-keys, 6 per round (the last 4 belong to the half round)
inline void printKeys(const char *title, const Keys &k) {
    std::cout << title << "\n";
    for (int r = 0; r < 5; r++) {
        std::cout << "  Round " << (r + 1) << ": ";
        int n = (r < 4) ? 6 : 4;
        for (int i = 0; i < n; i++) std::cout << util::toBin(k[6 * r + i], 4) << " ";
        std::cout << "\n";
    }
}

// Encrypt: pad (PKCS style: pad bytes all equal the pad length, 1 or 2),
// then encrypt each 2-byte block. verbose = print every round.
inline util::Bytes encrypt(const util::Bytes &msg, uint32_t key, bool verbose) {
    Keys z = expandKey(key);
    if (verbose) printKeys("Encryption sub-keys:", z);

    util::Bytes p = msg;
    uint8_t padLen = (uint8_t)(2 - (p.size() % 2));
    for (int i = 0; i < padLen; i++) p.push_back(padLen);

    util::Bytes out;
    for (size_t i = 0; i < p.size(); i += 2) {
        uint16_t blk = (uint16_t)((p[i] << 8) | p[i + 1]);
        std::vector<uint16_t> ro;
        uint16_t c = cryptBlock(blk, z, &ro);
        if (verbose) {
            std::cout << "Block " << (i / 2 + 1) << " plaintext : " << util::toBin(blk, 16) << "\n";
            for (size_t r = 0; r < ro.size(); r++)
                std::cout << "  After round " << (r + 1) << (r == 4 ? " (half)" : "") << ": "
                          << util::toBin(ro[r], 16) << "\n";
            std::cout << "Block " << (i / 2 + 1) << " ciphertext: " << util::toBin(c, 16) << "\n";
        }
        out.push_back((uint8_t)(c >> 8));
        out.push_back((uint8_t)(c & 0xFF));
    }
    return out;
}

// Decrypt: same block function with decryption sub-keys, then remove padding.
// Throws std::runtime_error if the padding is invalid (wrong key / corrupt data).
inline util::Bytes decrypt(const util::Bytes &ct, uint32_t key, bool verbose) {
    if (ct.size() == 0 || ct.size() % 2 != 0)
        throw std::runtime_error("ciphertext length must be a non-zero multiple of 2 bytes");
    Keys d = decryptionKeys(expandKey(key));
    if (verbose) printKeys("Decryption sub-keys:", d);

    util::Bytes p;
    for (size_t i = 0; i < ct.size(); i += 2) {
        uint16_t blk = (uint16_t)((ct[i] << 8) | ct[i + 1]);
        std::vector<uint16_t> ro;
        uint16_t m = cryptBlock(blk, d, &ro);
        if (verbose) {
            std::cout << "Block " << (i / 2 + 1) << " ciphertext: " << util::toBin(blk, 16) << "\n";
            for (size_t r = 0; r < ro.size(); r++)
                std::cout << "  After round " << (r + 1) << (r == 4 ? " (half)" : "") << ": "
                          << util::toBin(ro[r], 16) << "\n";
            std::cout << "Block " << (i / 2 + 1) << " plaintext : " << util::toBin(m, 16) << "\n";
        }
        p.push_back((uint8_t)(m >> 8));
        p.push_back((uint8_t)(m & 0xFF));
    }
    uint8_t padLen = p.back();
    if (padLen < 1 || padLen > 2 || padLen > p.size())
        throw std::runtime_error("bad padding (wrong key or corrupted data)");
    for (int i = 0; i < padLen; i++)
        if (p[p.size() - 1 - i] != padLen) throw std::runtime_error("bad padding");
    p.resize(p.size() - padLen);
    return p;
}

} // namespace idea
#endif