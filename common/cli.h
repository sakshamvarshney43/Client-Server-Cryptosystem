/*
 * File    : cli.h
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Command-line helpers shared by client and server:
 *           banner with name/roll number, safe number input, safe printing.
 */
#ifndef CLI_H
#define CLI_H

#include <iostream>
#include <string>
#include <cstdint>
#include <stdexcept>
#include "util.h"

namespace cli {

// Heading printed at the start of each program (name + roll number, as the assignment requires)
inline void banner(const char *role) {
    std::cout << "==============================================\n"
              << " " << role << "\n"
              << " Name    : " << AUTHOR_NAME << "\n"
              << " Roll No : " << AUTHOR_ROLL << "\n"
              << "==============================================\n";
}

inline std::string trim(const std::string &s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) a++;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) b--;
    return s.substr(a, b - a);
}

// Decimal text -> number. Returns false for empty text, non-digits or overflow.
inline bool parseU64(const std::string &text, uint64_t &out) {
    std::string s = trim(text);
    if (s.empty()) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < s.size(); i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (0xFFFFFFFFFFFFFFFFULL - d) / 10) return false;   // would overflow 64 bits
        v = v * 10 + d;
    }
    out = v;
    return true;
}

// Prints a prompt and reads one line. Throws if the input stream is closed.
inline std::string ask(const std::string &prompt) {
    std::cout << prompt << std::flush;
    std::string line;
    if (!std::getline(std::cin, line)) throw std::runtime_error("input closed");
    return trim(line);
}

// Asks until the user types a valid whole number
inline uint64_t askNumber(const std::string &prompt) {
    for (;;) {
        uint64_t v;
        if (parseU64(ask(prompt), v)) return v;
        std::cout << "  Invalid input: please enter a positive whole number.\n";
    }
}

// Asks until the user types exactly 8 hex digits (a 32-bit key)
inline uint32_t askHex32(const std::string &prompt) {
    for (;;) {
        std::string s = ask(prompt);
        bool ok = (s.size() == 8);
        uint32_t v = 0;
        for (size_t i = 0; ok && i < s.size(); i++) {
            try { v = (v << 4) | (uint32_t)util::hexVal(s[i]); } catch (...) { ok = false; }
        }
        if (ok) return v;
        std::cout << "  Invalid input: the secret key must be exactly 8 hex digits (0-9, A-F), e.g. DC6F3F59.\n";
    }
}

// Text safe to print: control characters / non-ASCII bytes shown as '.'
inline std::string printable(const std::string &s) {
    std::string r = s;
    for (size_t i = 0; i < r.size(); i++)
        if ((unsigned char)r[i] < 32 || (unsigned char)r[i] > 126) r[i] = '.';
    return r;
}

} // namespace cli
#endif