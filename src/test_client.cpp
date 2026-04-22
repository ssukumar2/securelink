#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

extern "C" {
#include "crypto_engine.h"
}

int main()
{
    std::cout << "securelink test client" << std::endl;

    // Generate client keypair
    ecc_keypair_t* kp = ecc_keypair_create();
    if (!kp)
    {
        std::cerr << "failed to generate keypair" << std::endl;
        return 1;
    }

    uint8_t client_pub[64];
    ecc_get_public_key(kp, client_pub, sizeof(client_pub));
    std::cout << "generated client keypair" << std::endl;

    // Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(sock, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << "connection failed (is the server running?)" << std::endl;
        ecc_keypair_free(kp);
        return 1;
    }
    std::cout << "connected to server" << std::endl;

    // Send client public key
    send(sock, client_pub, 64, 0);
    std::cout << "sent public key (64 bytes)" << std::endl;

    // Receive server response: pubkey[64] + ciphertext[16]
    uint8_t response[80];
    ssize_t received = recv(sock, response, sizeof(response), 0);
    close(sock);

    if (received != 80)
    {
        std::cerr << "unexpected response size: " << received << std::endl;
        ecc_keypair_free(kp);
        return 1;
    }
    std::cout << "received response (80 bytes)" << std::endl;

    // Derive shared secret
    uint8_t server_pub[64];
    uint8_t ciphertext[16];
    std::memcpy(server_pub, response, 64);
    std::memcpy(ciphertext, response + 64, 16);

    uint8_t shared_secret[32];
    int slen = ecc_derive_shared_secret(kp, server_pub, 64,
                                         shared_secret, sizeof(shared_secret));
    ecc_keypair_free(kp);

    if (slen < 0)
    {
        std::cerr << "ecdh derivation failed" << std::endl;
        return 1;
    }
    std::cout << "derived shared secret" << std::endl;

    // Decrypt
    uint8_t decrypted[16];
    int dec = aes256_ecb_decrypt(shared_secret, ciphertext, 16,
                                  decrypted, sizeof(decrypted));
    if (dec < 0)
    {
        std::cerr << "decryption failed" << std::endl;
        return 1;
    }

    std::string message(reinterpret_cast<char*>(decrypted), 16);
    // Trim null padding
    size_t end = message.find('\0');
    if (end != std::string::npos) message = message.substr(0, end);

    std::cout << "decrypted message: " << message << std::endl;

    if (message == "U2VjbG91cyBHbWJI")
    {
        std::cout << "HANDSHAKE VERIFIED SUCCESSFULLY" << std::endl;
        return 0;
    }
    else
    {
        std::cerr << "handshake verification failed" << std::endl;
        return 1;
    }
}