/*
 * File    : util.h
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Small helper functions shared by client and server
 *           (hex <-> bytes, binary printing). No external libraries.
 */
#ifndef UTIL_H
#define UTIL_H

#include <string>
#include <vector>
#include <cstdint>
#include <stdexcept>

#define AUTHOR_NAME "Saksham Varshney"
#define AUTHOR_ROLL "44300"

namespace util {

typedef std::vector<uint8_t> Bytes;

// Bytes -> uppercase hex string, e.g. {0xAB,0x01} -> "AB01"
inline std::string toHex(const Bytes &b) {
    static const char *H = "0123456789ABCDEF";
    std::string s;
    s.reserve(b.size() * 2);
    for (size_t i = 0; i < b.size(); i++) {
        s += H[b[i] >> 4];
        s += H[b[i] & 0x0F];
    }
    return s;
}

// Hex char -> value (0..15), throws on bad char
inline int hexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    throw std::invalid_argument("invalid hex character");
}

// Hex string -> bytes, e.g. "AB01" -> {0xAB,0x01}
inline Bytes fromHex(const std::string &s) {
    if (s.size() % 2 != 0) throw std::invalid_argument("hex length must be even");
    Bytes b;
    for (size_t i = 0; i < s.size(); i += 2)
        b.push_back((uint8_t)((hexVal(s[i]) << 4) | hexVal(s[i + 1])));
    return b;
}

// Value -> binary string of 'width' bits, e.g. toBin(5,4) -> "0101"
inline std::string toBin(uint32_t v, int width) {
    std::string s;
    for (int i = width - 1; i >= 0; i--) s += ((v >> i) & 1) ? '1' : '0';
    return s;
}

// String <-> bytes (message text)
inline Bytes strToBytes(const std::string &s) { return Bytes(s.begin(), s.end()); }
inline std::string bytesToStr(const Bytes &b) { return std::string(b.begin(), b.end()); }

} // namespace util
#endif