/*
 * File    : rsa.h
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : RSA written from scratch: key generation, encryption/decryption
 *           of the secret key, and digital signature (sign/verify) over a hash.
 *           Numbers are 64-bit (n < 2^64, so p and q must be below 2^32).
 *           No big-number library and no compiler-specific 128-bit type is used,
 *           so the code compiles unchanged on Windows, Linux and macOS.
 *           Rule: n must be > 2^32 so that a 32-bit chunk always fits below n.
 */
#ifndef RSA_H
#define RSA_H

#include <cstdint>
#include <string>
#include <vector>
#include <stdexcept>
#include "util.h"

namespace rsa {

typedef uint64_t u64;

struct PublicKey  { u64 e; u64 n; };
struct PrivateKey { u64 d; u64 n; };
struct KeyPair {
    u64 p, q, n, phi, e, d;
    PublicKey  pub()  const { PublicKey k  = { e, n }; return k; }
    PrivateKey priv() const { PrivateKey k = { d, n }; return k; }
};

/* ---------------- modular arithmetic (no overflow, no 128-bit type) ---------------- */

// (a + b) mod m, for a,b < m, without overflowing 64 bits
inline u64 addmod(u64 a, u64 b, u64 m) { return (a >= m - b) ? a - (m - b) : a + b; }

// (a * b) mod m by "double and add" (like long multiplication in binary)
inline u64 mulmod(u64 a, u64 b, u64 m) {
    u64 r = 0;
    a %= m; b %= m;
    while (b) {
        if (b & 1) r = addmod(r, a, m);
        a = addmod(a, a, m);
        b >>= 1;
    }
    return r;
}

// (base ^ exp) mod m by square-and-multiply
inline u64 powmod(u64 base, u64 exp, u64 m) {
    u64 r = 1 % m;
    base %= m;
    while (exp) {
        if (exp & 1) r = mulmod(r, base, m);
        base = mulmod(base, base, m);
        exp >>= 1;
    }
    return r;
}

inline u64 gcd(u64 a, u64 b) { while (b) { u64 t = a % b; a = b; b = t; } return a; }

// modular inverse of a modulo m (extended Euclid); throws if gcd(a,m) != 1
inline u64 modInverse(u64 a, u64 m) {
    u64 r0 = m, r1 = a % m;
    u64 t0 = 0, t1 = 1;                       // invariant: t * a = r (mod m)
    while (r1 != 0) {
        u64 q = r0 / r1;
        u64 r2 = r0 - q * r1;
        u64 qt = mulmod(q, t1, m);
        u64 t2 = (t0 >= qt) ? t0 - qt : t0 + (m - qt);
        r0 = r1; r1 = r2;
        t0 = t1; t1 = t2;
    }
    if (r0 != 1) throw std::invalid_argument("no modular inverse (numbers not coprime)");
    return t0;
}

// Miller-Rabin primality test; these 12 bases are exact for every 64-bit number
inline bool isPrime(u64 n) {
    if (n < 2) return false;
    static const u64 small[12] = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37};
    for (int i = 0; i < 12; i++) {
        if (n == small[i]) return true;
        if (n % small[i] == 0) return false;
    }
    u64 d = n - 1; int s = 0;
    while ((d & 1) == 0) { d >>= 1; s++; }
    for (int i = 0; i < 12; i++) {
        u64 x = powmod(small[i], d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int r = 1; r < s; r++) {
            x = mulmod(x, x, n);
            if (x == n - 1) { composite = false; break; }
        }
        if (composite) return false;
    }
    return true;
}

/* ---------------- key generation ---------------- */

// Input = key generation parameters: primes p, q and public exponent e.
// n = p*q, phi = (p-1)(q-1), d = e^-1 mod phi.  Throws with a clear message if invalid.
inline KeyPair generateKeys(u64 p, u64 q, u64 e) {
    if (p >= 4294967296ULL || q >= 4294967296ULL) throw std::invalid_argument("p and q must be below 2^32");
    if (!isPrime(p)) throw std::invalid_argument("p is not prime");
    if (!isPrime(q)) throw std::invalid_argument("q is not prime");
    if (p == q)      throw std::invalid_argument("p and q must be different");
    KeyPair k;
    k.p = p; k.q = q;
    k.n = p * q;                               // < 2^64 because p,q < 2^32
    if (k.n <= 4294967295ULL) throw std::invalid_argument("p*q must be greater than 2^32 (choose larger primes)");
    k.phi = (p - 1) * (q - 1);
    if (e <= 1 || e >= k.phi) throw std::invalid_argument("e must satisfy 1 < e < phi(n)");
    if (gcd(e, k.phi) != 1)   throw std::invalid_argument("e must be coprime with phi(n)");
    k.e = e;
    k.d = modInverse(e, k.phi);
    return k;
}

/* ---------------- encrypt / decrypt the 32-bit secret key ---------------- */

inline u64 encryptKey(uint32_t secret, const PublicKey &pub) { return powmod(secret, pub.e, pub.n); }

inline uint32_t decryptKey(u64 cipher, const PrivateKey &priv) {
    u64 m = powmod(cipher, priv.d, priv.n);
    if (m > 0xFFFFFFFFULL) throw std::runtime_error("decrypted secret key out of range (wrong keys?)");
    return (uint32_t)m;
}

/* ---------------- digital signature over a hash ---------------- */
// The hash (64 bytes for Whirlpool) is cut into 4-byte chunks; each chunk is
// signed separately:  sig = chunk ^ d mod n.  Verification: sig ^ e mod n == chunk.

inline std::vector<u64> sign(const util::Bytes &digest, const PrivateKey &priv) {
    if (digest.size() % 4 != 0) throw std::invalid_argument("digest length must be a multiple of 4");
    std::vector<u64> sigs;
    for (size_t i = 0; i < digest.size(); i += 4) {
        u64 chunk = ((u64)digest[i] << 24) | ((u64)digest[i + 1] << 16) | ((u64)digest[i + 2] << 8) | digest[i + 3];
        sigs.push_back(powmod(chunk, priv.d, priv.n));
    }
    return sigs;
}

// Recovers the hash hidden in the signature using the client's public key.
// Returns false if a recovered value does not fit in 32 bits (certainly invalid).
inline bool recoverHash(const std::vector<u64> &sigs, const PublicKey &pub, util::Bytes &recovered) {
    recovered.clear();
    for (size_t i = 0; i < sigs.size(); i++) {
        u64 v = powmod(sigs[i], pub.e, pub.n);
        if (v > 0xFFFFFFFFULL) return false;
        for (int s = 24; s >= 0; s -= 8) recovered.push_back((uint8_t)((v >> s) & 0xFF));
    }
    return true;
}

// true if the signature matches the hash we computed ourselves
inline bool verify(const util::Bytes &digest, const std::vector<u64> &sigs, const PublicKey &pub,
                   util::Bytes *recoveredOut = 0) {
    util::Bytes rec;
    bool ok = recoverHash(sigs, pub, rec);
    if (recoveredOut) *recoveredOut = rec;
    return ok && rec == digest;
}

/* ---------------- text form for sending over the socket ---------------- */

inline std::string u64ToHex(u64 v) {                  // always 16 hex digits
    static const char *H = "0123456789ABCDEF";
    std::string s(16, '0');
    for (int i = 15; i >= 0; i--) { s[i] = H[v & 0xF]; v >>= 4; }
    return s;
}

inline u64 hexToU64(const std::string &s) {
    if (s.empty() || s.size() > 16) throw std::invalid_argument("bad hex number");
    u64 v = 0;
    for (size_t i = 0; i < s.size(); i++) v = (v << 4) | (u64)util::hexVal(s[i]);
    return v;
}

inline std::string sigsToHex(const std::vector<u64> &sigs) {
    std::string s;
    for (size_t i = 0; i < sigs.size(); i++) s += u64ToHex(sigs[i]);
    return s;
}

inline std::vector<u64> sigsFromHex(const std::string &s) {
    if (s.size() % 16 != 0) throw std::invalid_argument("signature hex length must be a multiple of 16");
    std::vector<u64> v;
    for (size_t i = 0; i < s.size(); i += 16) v.push_back(hexToU64(s.substr(i, 16)));
    return v;
}

} // namespace rsa
#endif