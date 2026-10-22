/*
 * File    : server.cpp
 * Author  : Saksham Varshney
 * Roll No : 44300
 * Purpose : Server of the secure message exchange (Assignment 1).
 *           Symmetric : Simplified IDEA       Asymmetric : RSA
 *           Hash      : Whirlpool (from scratch)
 *
 * Usage   : server [port]          (default port 5000)
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

// text of the key parameters, as shown in the "Input:" part of the output
static string publicKeyText(const rsa::KeyPair &kp) {
    return "(e = " + to_string(kp.e) + ", n = " + to_string(kp.n) + ")";
}
static string privateKeyText(const rsa::KeyPair &kp) {
    return "(d = " + to_string(kp.d) + ", n = " + to_string(kp.n) + ", p = " + to_string(kp.p) +
           ", q = " + to_string(kp.q) + ", phi(n) = " + to_string(kp.phi) + ")";
}

// Server side computation for one MSG line. Returns true if the message is accepted.
// Throws std::exception (with a readable text) if the data cannot even be processed.
// sectionStarted becomes true once the "Server Side:" part of the output has begun.
static bool processMessage(const string &line, const rsa::KeyPair &kp, string &reason, bool &sectionStarted) {
    vector<string> t = splitWords(line);
    if (t.size() != 6 || t[0] != "MSG") throw runtime_error("bad MSG format");

    // ---- parse what the client sent ----
    util::Bytes cipher = util::fromHex(t[1]);                 // IDEA ciphertext
    rsa::u64 encKey = rsa::hexToU64(t[2]);                    // RSA-encrypted secret key
    vector<rsa::u64> sigs = rsa::sigsFromHex(t[3]);           // client signature
    rsa::PublicKey clientPub;
    if (!cli::parseU64(t[4], clientPub.e) || !cli::parseU64(t[5], clientPub.n))
        throw runtime_error("bad client public key");
    if (clientPub.n <= 0xFFFFFFFFULL || clientPub.e < 2)      // also protects against n = 0
        throw runtime_error("invalid client public key");

    // what arrived (connection log - printed BEFORE the formatted "Server Side" section)
    cout << "Received from client: ciphertext (" << cipher.size() << " bytes), encrypted secret key, signature, client public key\n";
    cout << "  Received client public key    : (e = " << clientPub.e << ", n = " << clientPub.n << ")\n";
    cout << "  Received encrypted secret key : " << t[2] << "\n";
    cout << "  Received ciphertext           : " << t[1] << "\n";
    cout << "  Received client signature     : " << t[3] << "\n";

    // ================= main output section: format of the assignment PDF =================
    cout << "\nServer Side:\n\n";
    sectionStarted = true;
    cout << "Input:\n";
    cout << "  Public Key parameters: " << publicKeyText(kp) << "\n";
    cout << "  Private key parameters: " << privateKeyText(kp) << "\n\n";

    // 1. decrypt the secret key with the server private key
    uint32_t secret = rsa::decryptKey(encKey, kp.priv());
    util::Bytes keyBytes;
    for (int s = 24; s >= 0; s -= 8) keyBytes.push_back((uint8_t)((secret >> s) & 0xFF));
    cout << "Decrypted Secret key: " << util::toHex(keyBytes) << "\n\n";

    // 2. decrypt the ciphertext with Simplified IDEA (prints every round)
    cout << "Intermediate decryption process:\n";
    util::Bytes plain;
    try {
        plain = idea::decrypt(cipher, secret, true);
    } catch (const exception &ex) {
        throw runtime_error(string("IDEA decryption failed: ") + ex.what());
    }
    cout << "\nDecrypt Message: " << cli::printable(util::bytesToStr(plain)) << "\n";

    // 3. hash of the decrypted message
    util::Bytes digest = whirlpool::hash(plain);
    cout << "Hash code: " << util::toHex(digest) << "\n";

    // 4. verify the signature: recover the hash from it with the client public key
    util::Bytes recovered;
    bool valid = rsa::verify(digest, sigs, clientPub, &recovered);
    cout << "Verification code: " << util::toHex(recovered) << "\n";
    cout << "Signature: " << (valid ? "valid" : "invalid") << "\n";
    cout << "Message: " << (valid ? "Accepted" : "Rejected") << "\n";
    if (!valid) reason = "signature invalid";
    return valid;
}

// talk to one connected client (protocol described at the top of the file)
static void handleClient(net::Socket &c, const rsa::KeyPair &kp) {
    string line;

    // step 1: client asks for our public key
    if (!c.recvLine(line)) { cout << "Client disconnected without sending anything.\n"; return; }
    if (line != "GET_PUBKEY") {
        c.sendLine("ERROR expected GET_PUBKEY");
        cout << "Unexpected first message from client - connection dropped.\n";
        return;
    }
    cout << "Client requested the server public key -> sending (e, n)\n";
    c.sendLine("PUBKEY " + to_string(kp.e) + " " + to_string(kp.n));

    // step 2: client sends ciphertext + encrypted secret key + signature + its public key
    if (!c.recvLine(line)) { cout << "Client disconnected before sending the message.\n"; return; }
    string reason;
    bool accepted = false;
    bool sectionStarted = false;
    try {
        accepted = processMessage(line, kp, reason, sectionStarted);
    } catch (const exception &ex) {
        // the data could not be processed: always shown as Rejected, never as Accepted
        reason = ex.what();
        if (!sectionStarted) cout << "\nServer Side:\n\n";
        cout << "\nMessage: Rejected (" << reason << ")\n";
    }
    cout << "-----------------------------------------------\n\n";
    c.sendLine(accepted ? string("RESULT ACCEPTED") : "RESULT REJECTED " + reason);
}

int main(int argc, char **argv) {
    cli::banner("SECURE MESSAGE EXCHANGE - SERVER");

    // ---- port ----
    int port = 5000;
    if (argc >= 2) {
        uint64_t v;
        if (!cli::parseU64(argv[1], v) || v < 1 || v > 65535) {
            cerr << "Usage: server [port]   (port must be 1-65535)\n";
            return 1;
        }
        port = (int)v;
    }

    try {
        // ---- server inputs: public and private key parameters ----
        rsa::KeyPair kp;
        for (;;) {
            cout << "\nEnter the RSA key generation parameters for the server\n";
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
        cout << "\nInput:\n"
             << "  Key generation parameters : p = " << kp.p << ", q = " << kp.q << ", e = " << kp.e << "\n"
             << "  Public Key parameters     : (e = " << kp.e << ", n = " << kp.n << ")\n"
             << "  Private key parameters    : (d = " << kp.d << ", n = " << kp.n << ")   [phi(n) = " << kp.phi << "]\n";

        // ---- wait for clients, one after another ----
        net::Socket listener;
        listener.listenOn(port);
        cout << "\nServer listening on port " << port << "  (press Ctrl+C to stop)\n";

        int failures = 0;
        for (;;) {
            try {
                string peer;
                net::Socket client = listener.acceptClient(&peer);
                failures = 0;
                cout << "\n>>> Client connected: " << peer << "\n";
                handleClient(client, kp);
                cout << ">>> Client finished, waiting for the next one...\n";
            } catch (const exception &ex) {
                cout << "Connection problem: " << ex.what() << "\n";
                if (++failures >= 5) { cout << "Too many errors in a row - stopping.\n"; return 1; }
            }
        }
    } catch (const exception &ex) {
        cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    }
}