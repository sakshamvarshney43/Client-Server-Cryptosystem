/*
 * File    : client.cpp
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Client of the secure message exchange (Assignment 1).
 *           Symmetric : Simplified IDEA       Asymmetric : RSA
 *           Hash      : Whirlpool (from scratch)
 *
 * Usage   : client [server_ip] [port]      (defaults: 127.0.0.1 and 5000)
 *
 * What the client does:
 *   1. asks for the message, the 32-bit secret key and its own RSA parameters (p, q, e)
 *   2. requests the server public key
 *   3. encrypts the secret key with the SERVER public key (RSA)
 *   4. encrypts the message with the secret key (Simplified IDEA)
 *   5. computes the Whirlpool hash of the message and signs it with its OWN private key (RSA)
 *   6. sends  ciphertext + encrypted secret key + signature + client public key
 *
 * Protocol (one text line per message, TCP):
 *   client -> GET_PUBKEY
 *   server -> PUBKEY <e> <n>
 *   client -> MSG <ciphertext hex> <encrypted secret key hex> <signature hex> <client e> <client n>
 *   server -> RESULT ACCEPTED   |   RESULT REJECTED <reason>
 */
#include "common/net.h"          // keep this FIRST: it pulls in the Windows socket headers
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "common/util.h"
#include "common/idea.h"
#include "common/whirlpool.h"
#include "common/rsa.h"
#include "common/cli.h"

using namespace std;

// split a line into words separated by spaces
static vector<string> splitWords(const string &line) {
    vector<string> w;
    istringstream in(line);
    string t;
    while (in >> t) w.push_back(t);
    return w;
}

// read the message exactly as typed (spaces are kept); must not be empty
static string readMessage() {
    for (;;) {
        cout << "Enter the message to send              : " << flush;
        string line;
        if (!getline(cin, line)) throw runtime_error("input closed");
        while (!line.empty() && (line[line.size() - 1] == '\r' || line[line.size() - 1] == '\n'))
            line.erase(line.size() - 1);
        if (line.empty()) { cout << "  The message cannot be empty.\n"; continue; }
        if (line.size() > 100000) { cout << "  The message is too long (maximum 100000 characters).\n"; continue; }
        return line;
    }
}

// text of the key parameters, as shown in the "Input:" part of the output
static string publicKeyText(const rsa::KeyPair &kp) {
    return "(e = " + to_string(kp.e) + ", n = " + to_string(kp.n) + ")";
}
static string privateKeyText(const rsa::KeyPair &kp) {
    return "(d = " + to_string(kp.d) + ", n = " + to_string(kp.n) + ", p = " + to_string(kp.p) +
           ", q = " + to_string(kp.q) + ", phi(n) = " + to_string(kp.phi) + ")";
}

static util::Bytes keyToBytes(uint32_t k) {
    util::Bytes b;
    for (int s = 24; s >= 0; s -= 8) b.push_back((uint8_t)((k >> s) & 0xFF));
    return b;
}

int main(int argc, char **argv) {
    cli::banner("SECURE MESSAGE EXCHANGE - CLIENT");

    // ---- server address ----
    string host = "127.0.0.1";
    int port = 5000;
    if (argc > 3) { cerr << "Usage: client [server_ip] [port]\n"; return 1; }
    if (argc >= 2) host = argv[1];
    if (argc >= 3) {
        uint64_t v;
        if (!cli::parseU64(argv[2], v) || v < 1 || v > 65535) {
            cerr << "Usage: client [server_ip] [port]   (port must be 1-65535)\n";
            return 1;
        }
        port = (int)v;
    }

    try {
        // ---- client inputs: message, secret key, public and private key parameters ----
        string message = readMessage();
        uint32_t secret = cli::askHex32("Enter the secret key (8 hex digits)     : ");

        rsa::KeyPair kp;
        for (;;) {
            cout << "\nEnter the RSA key generation parameters for the client\n";
            rsa::u64 p = cli::askNumber("  prime p                : ");
            rsa::u64 q = cli::askNumber("  prime q                : ");
            rsa::u64 e = cli::askNumber("  public exponent e      : ");
            try {
                kp = rsa::generateKeys(p, q, e);
                break;
            } catch (const exception &ex) {
                cout << "  Error: " << ex.what() << "\nPlease enter the parameters again.\n";
            }
        }

        // ---- ask the server for its public key (connection log, printed BEFORE the formatted section) ----
        cout << "\nConnecting to server " << host << ":" << port << " ...\n";
        net::Socket s;
        s.connectTo(host, port);
        cout << "Connected. Requesting the server public key...\n";
        s.sendLine("GET_PUBKEY");

        string line;
        if (!s.recvLine(line)) throw runtime_error("the server closed the connection");
        vector<string> t = splitWords(line);
        rsa::PublicKey serverPub;
        if (t.size() != 3 || t[0] != "PUBKEY" || !cli::parseU64(t[1], serverPub.e) || !cli::parseU64(t[2], serverPub.n))
            throw runtime_error("unexpected reply from the server: " + cli::printable(line.substr(0, 100)));
        if (serverPub.n <= 0xFFFFFFFFULL || serverPub.e < 2)
            throw runtime_error("the server sent an invalid public key");
        cout << "Server public key received: (e = " << serverPub.e << ", n = " << serverPub.n << ")\n";

        // ================= main output section: format of the assignment PDF =================
        cout << "\nClient Side:\n\n"
             << "Input:\n"
             << "  Message: " << cli::printable(message) << "\n"
             << "  Secret Key: " << util::toHex(keyToBytes(secret)) << "\n"
             << "  Public Key parameters: " << publicKeyText(kp) << "\n"
             << "  Private key parameters: " << privateKeyText(kp) << "\n\n";

        // ---- 1. encrypt the secret key with the server public key (RSA) ----
        rsa::u64 encKey = rsa::encryptKey(secret, serverPub);
        string encKeyHex = rsa::u64ToHex(encKey);
        cout << "Encrypted Secret Key: " << encKeyHex << "\n\n";

        // ---- 2. encrypt the message with Simplified IDEA (prints every round) ----
        util::Bytes msgBytes = util::strToBytes(message);
        cout << "Intermediate encryption process:\n";
        util::Bytes cipher = idea::encrypt(msgBytes, secret, true);
        string cipherHex = util::toHex(cipher);
        cout << "\nCipher text: " << cipherHex << "\n";

        // ---- 3. hash of the message (Whirlpool) ----
        util::Bytes digest = whirlpool::hash(msgBytes);
        cout << "Hash code: " << util::toHex(digest) << "\n";

        // ---- 4. digital signature over the hash with the client private key (RSA) ----
        string sigHex = rsa::sigsToHex(rsa::sign(digest, kp.priv()));
        cout << "Digital Signature: " << sigHex << "\n";
        cout << "-----------------------------------------------\n\n";

        // ---- send everything ----
        s.sendLine("MSG " + cipherHex + " " + encKeyHex + " " + sigHex + " " +
                   to_string(kp.e) + " " + to_string(kp.n));
        cout << "Sent: ciphertext + encrypted secret key + client signature + client public key\n";

        if (!s.recvLine(line)) throw runtime_error("the server closed the connection without an answer");
        cout << "Server response: " << cli::printable(line) << "\n";
        return line == "RESULT ACCEPTED" ? 0 : 2;

    } catch (const exception &ex) {
        cerr << "\nError: " << ex.what() << "\n";
        return 1;
    }
}