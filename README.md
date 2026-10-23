# Secure Message Exchange

**Language:** C++ (C++11 or later)  
**Author:** Saksham Varshney  
**Roll Number:** 44300  
**Course work:** Computer Networks, Assignment 1

## Project overview

This project has a client and a server that exchange a message over TCP. The
client encrypts the message with Simplified IDEA, encrypts the IDEA secret key
with the server's RSA public key, and signs the Whirlpool hash of the message
with its own RSA private key. The server decrypts the key and the message,
calculates the hash again, and checks the signature. The message is accepted
only when the signature is valid.

1. The client asks the server for its public key.
2. The server sends it.
3. The client sends the cipher text, the encrypted secret key, its signature and
   its public key.
4. The server decrypts, hashes, verifies, and answers `ACCEPTED` or `REJECTED`.

The project uses only the C++ standard library and the socket API that is part
of the operating system, so nothing has to be installed. Everything, including
the cipher, the hash and RSA, is written from scratch.

## Algorithms (assigned by roll number 44300)

- **Simplified IDEA** (44300 % 3 = 2): encrypts and decrypts 16-bit blocks with
  a 32-bit key, using 4 rounds and a final half round. The program prints the
  state after every round for every block.
- **RSA** (44300 % 2 = 0): creates the public and private keys from the primes
  `p`, `q` and the exponent `e`, encrypts the IDEA key, and creates and checks
  the digital signature.
- **Whirlpool:** calculates a 512-bit hash. The S-box is generated from the
  small boxes of the specification, not copied from a table.

The sample primes are around one million, which is enough for a local
demonstration. RSA works with numbers below 2^64, so it is too small to protect
real messages. The public key is sent openly over plain TCP; the demo does not
authenticate the server and does not use TLS.

## Build on Windows

Open PowerShell in the project folder and run `.\build.bat`, or build by hand
(needs MinGW-w64 `g++`):

```powershell
g++ -std=gnu++11 -O2 -static -static-libgcc -static-libstdc++ server.cpp -o server.exe -lws2_32
g++ -std=gnu++11 -O2 -static -static-libgcc -static-libstdc++ client.cpp -o client.exe -lws2_32
```

`-lws2_32` links the Windows socket library; it is part of Windows, not a
third-party library. The `-static` options put the C++ runtime inside the
`.exe`, so the prebuilt `server.exe` and `client.exe` in this folder run on a
Windows PC with nothing installed.

## Build on Linux

```sh
g++ -std=c++11 -O2 server.cpp -o server
g++ -std=c++11 -O2 client.cpp -o client
```

## Run the programs

For a one-click run on Windows, double-click `run_server.bat`, then
`run_client.bat`. Each window stays open after the program ends.

To run them manually, open two terminals in the project folder:

1. Start the server: `.\server.exe` (Linux: `./server`). Enter the server's
   `p`, `q` and `e`.
2. Start the client: `.\client.exe` (Linux: `./client`). Enter a message, the
   secret key as 8 hex digits, and the client's `p`, `q` and `e`.

The default port is `5000`. The server accepts another port, for example
`.\server.exe 9000`, and the client accepts the server address and port, for
example `.\client.exe 127.0.0.1 9000`. The server keeps running and serves one
client after another.

| Program | Prompt                    | Sample value                  |
| ------- | ------------------------- | ----------------------------- |
| Server  | `p`, `q`, `e`             | `1000037`, `1000039`, `65537` |
| Client  | message                   | `Hello from Saksham`          |
| Client  | secret key (8 hex digits) | `DC6F3F59`                    |
| Client  | `p`, `q`, `e`             | `1000003`, `1000033`, `65537` |

With these values the server prints `Signature: valid` and `Message: Accepted`,
and the client prints `Server response: RESULT ACCEPTED`. Windows may ask once
whether the server may use the network; choose **Allow**.

## Output

Both programs print a banner with the name and roll number first. The main
output follows the assignment format. Connection messages are printed outside
these blocks.

```
Client Side:                                 Server Side:

Input:                                       Input:
  Message: ...                                 Public Key parameters: ...
  Secret Key: ...                              Private key parameters: ...
  Public Key parameters: ...
  Private key parameters: ...                Decrypted Secret key: ...

Encrypted Secret Key: ...                    Intermediate decryption process:
                                               (round-by-round trace)
Intermediate encryption process:
  (round-by-round trace)                     Decrypt Message: ...
                                             Hash code: ...
Cipher text: ...                             Verification code: ...
Hash code: ...                               Signature: valid / invalid
Digital Signature: ...                       Message: Accepted / Rejected
```

- Public Key parameters are shown as `(e, n)`. Private key parameters are shown
  as `(d, n, p, q, phi(n))`.
- The verification code is the hash recovered from the client's signature with
  the client's public key. It equals the hash code exactly when the signature
  is valid.
- If the received data cannot be processed, the server prints
  `Message: Rejected (reason)`. A message is never shown as accepted unless the
  signature is valid.

### Messages between client and server (one text line each)

| Direction       | Line                                                                                     |
| --------------- | ---------------------------------------------------------------------------------------- |
| client → server | `GET_PUBKEY`                                                                             |
| server → client | `PUBKEY <e> <n>`                                                                         |
| client → server | `MSG <cipher text hex> <encrypted secret key hex> <signature hex> <client e> <client n>` |
| server → client | `RESULT ACCEPTED` or `RESULT REJECTED <reason>`                                          |

## Files and main functions

- `client.cpp`: `main` reads the message, secret key and client keys, gets the
  server public key, encrypts, hashes, signs, sends the packet and prints the
  server's answer. `readMessage` reads the message exactly as typed and refuses
  an empty or very long one. `publicKeyText` and `privateKeyText` build the key
  lines of the output, `keyToBytes` turns the 32-bit key into 4 bytes for
  printing, and `splitWords` splits a protocol line.
- `server.cpp`: `main` reads the server keys, listens, and serves clients one
  after another. `handleClient` runs the message exchange with one client.
  `processMessage` does the server side work for one packet: it parses the
  packet, decrypts the secret key and the message, hashes, verifies the
  signature and prints the Server Side block. `publicKeyText`,
  `privateKeyText` and `splitWords` are the same helpers as in the client.
- `common/util.h`: `toHex` and `fromHex` convert bytes to and from hex text,
  `hexVal` converts one hex character, `toBin` prints a value in binary,
  `strToBytes` and `bytesToStr` convert text and bytes. It also holds the
  author name and roll number constants.
- `common/idea.h`: `add`, `mul`, `addInv` and `mulInv` are the nibble
  operations (mod 16 and mod 17). `expandKey` makes the 28 sub-keys from the
  32-bit key and `decryptionKeys` makes the decryption sub-keys.
  `cryptBlock` runs the 4 rounds and the half round on one 16-bit block, for
  both encryption and decryption. `printKeys` prints the sub-keys. `encrypt`
  pads the message and encrypts every block; `decrypt` decrypts every block and
  removes the padding.
- `common/whirlpool.h`: `gmul` multiplies in GF(2^8). `Tables` and `T` build
  the S-box and constants once. `round` is one round (substitution, column
  shift, row mixing, key XOR) and `compress` processes one 64-byte block.
  `hash` pads the input and returns the 64-byte digest; `hashHex` returns it as
  128 hex characters.
- `common/rsa.h`: `addmod`, `mulmod` and `powmod` calculate modular sums,
  products and powers without overflow. `gcd`, `modInverse` and `isPrime`
  support key generation. `generateKeys` checks `p`, `q`, `e` and returns the
  key pair. `encryptKey` and `decryptKey` handle the secret key. `sign` signs
  the hash in 4-byte pieces, `recoverHash` reads a signature back, and
  `verify` compares it with the hash calculated locally. `u64ToHex`,
  `hexToU64`, `sigsToHex` and `sigsFromHex` convert numbers and signatures to
  and from the text sent over the network.
- `common/net.h`: `Socket` connects (`connectTo`), listens (`listenOn`),
  accepts (`acceptClient`), sends a line (`sendLine`) and receives a line
  (`recvLine`). It closes itself automatically (`close`, `valid`). `init`
  starts Winsock on Windows, `checkPort` rejects bad ports and `errText` adds
  the system error code to a message.
- `common/cli.h`: `banner` prints the heading with name and roll number.
  `trim`, `parseU64`, `ask`, `askNumber` and `askHex32` read input safely, and
  `printable` hides control characters when printing received text.
- `build.bat`, `run_server.bat`, `run_client.bat`: build and start the programs
  on Windows.
- `screenshots/`: real screenshots of the client and server windows.

## Input checks

- The secret key must be exactly 8 hex digits, numbers must be whole numbers
  and the message cannot be empty. Wrong input is asked again.
- RSA values are checked (prime `p` and `q`, `p` different from `q`, `p*q`
  above 2^32, `e` coprime with `phi(n)`), and the reason is shown if they fail.
- A missing server, an unknown host or a bad port gives a readable message.
- The server rejects bad hex, wrong keys, invalid client keys and invalid
  signatures without stopping, and waits for the next client.

## Checks that were run

- Whirlpool matches OpenSSL and the standard values, including message lengths
  around the block boundary:
  - empty text: `19FA61D75522A4669B44E39C1D2E1726C530232130D407F89AFEE0964997F7A73E83BE698B288FEBCF88E3E03C4F0757EA8964E59B63D93708B138CC42A66EB3`
  - `a`: `8ACA2602792AEC6F11A67206531FB7D7F0DFF59413145E6973C45001D0087B42D11BC645413AEFF63A42391A39145A591A92200D560195E53B478584FDAE231A`
  - `abc`: `4E2448A4C6F486BB16B6562C73B4020BF3043E3A731BCE721AE1B303D97E6D4C7181EEBDB6C57E277D0E34957114CBD6C797FC9D95D8B582D225292076D4EEF5`
- Simplified IDEA reproduces the worked example of the course document (key
  `DC6F3F59`, plaintext `1001110010101100`, cipher text `1011101101001011`),
  and every round output of that example.
- RSA keys and cipher values were compared with an independent big-integer
  calculation.
- A normal exchange is accepted. A changed cipher text, a signature made with
  another key, a wrong secret key and malformed messages are rejected.

## Limits

- RSA uses numbers below 2^64, which is only suitable for demonstration.
- IDEA encrypts each 16-bit block on its own (ECB mode).
- The server handles one client at a time.

## Submission folder

```
client.cpp   server.cpp   common/   build.bat   run_server.bat   run_client.bat
client.exe   server.exe   README.md   screenshots/
```
