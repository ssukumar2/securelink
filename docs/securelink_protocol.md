# securelink handshake protocol

## Overview

securelink implements a single-round-trip key exchange and encryption protocol using elliptic curve cryptography (ECC) and AES-256 symmetric encryption over a TCP connection. The goal is to establish a shared symmetric key between two parties without either side transmitting the key itself. This is the same fundamental principle behind TLS, SSH, and other secure channel protocols.

## Cryptographic primitives

The protocol uses three operations from OpenSSL:

ECC key generation on the secp256r1 curve (also called NIST P-256). Each side generates a private key (a 256-bit random number) and a corresponding public key (a point on the elliptic curve). The private key never leaves the machine that generated it.

ECDH (Elliptic Curve Diffie-Hellman) shared secret derivation. Given your own private key and the other party's public key, ECDH produces a shared secret that both sides compute independently. The math guarantees both sides get the same result, but an eavesdropper who only sees the public keys cannot derive the secret.

AES-256-ECB encryption using the first 32 bytes of the shared secret as the key.

## Protocol steps

1. Client generates an ECC key pair on secp256r1
2. Client connects to server on TCP port 1234
3. Client sends its raw public key (64 bytes: 32 bytes x-coordinate + 32 bytes y-coordinate, no 0x04 prefix)
4. Server generates its own ECC key pair on secp256r1
5. Server derives a shared secret using ECDH with the client's public key and the server's private key
6. Server takes the first 32 bytes of the shared secret as the AES-256 key
7. Server encrypts a 16-byte test message with AES-256-ECB
8. Server sends its public key (64 bytes) followed by the ciphertext (16 bytes)
9. Client derives the same shared secret using ECDH with the server's public key and the client's private key
10. Client takes the first 32 bytes as the AES key and decrypts the ciphertext
11. If the decrypted message matches the expected plaintext, the handshake succeeded

## Wire format

Client to server: exactly 64 bytes

    Bytes 0-31:   x-coordinate of client's public key
    Bytes 32-63:  y-coordinate of client's public key

Server to client: exactly 80 bytes

    Bytes 0-31:   x-coordinate of server's public key
    Bytes 32-63:  y-coordinate of server's public key
    Bytes 64-79:  AES-256-ECB ciphertext (one 16-byte block)

## Why this works

The security rests on the elliptic curve discrete logarithm problem. An attacker who captures both public keys cannot compute the private keys, and without a private key they cannot derive the shared secret. The shared secret is never transmitted — both sides compute it independently from their own private key and the other's public key.

## Security limitations

AES-ECB encrypts each 16-byte block independently, which means identical plaintext blocks produce identical ciphertext blocks. For a single-block message this is fine, but for longer messages ECB leaks patterns. A production protocol should use AES-GCM, which provides both confidentiality and authentication in one operation.

There is no certificate or identity verification. An active attacker could intercept the connection and perform the handshake with both sides separately (man-in-the-middle). Fixing this requires either pre-shared public keys, a certificate authority, or a trust-on-first-use model.

The protocol has no message authentication code on the ciphertext. An attacker could flip bits in the ciphertext and the decryption would produce garbage without the receiver knowing. AES-GCM would solve this too, since it includes an authentication tag.

## Relationship to my thesis work

My Master's thesis at University of Passau (2022) covered authenticated TCP and UDP communication for the ASOA middleware in autonomous vehicles (UNICARagil project). I designed a key distribution protocol and validated it against the Dolev-Yao attacker model, which assumes the attacker can intercept, modify, replay, and forge any network message. securelink implements a simplified version of the same key exchange concepts in a standalone context.