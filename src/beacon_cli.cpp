// beacon_cli — standalone CLI for sending beacons. Useful for manual
// testing against a securelink server.
//
// Usage:
//   beacon_cli --host=127.0.0.1 --port=4443 --interval=2000 --count=10
//
// For now the key/IV are derived deterministically from a --secret string
// using HKDF, so two CLIs with the same --secret can talk to each other.

#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "beacon_client.hpp"
#include "cli_args.hpp"
#include "sl_hkdf.h"
#include "sl_id.h"
#include "sl_kdf_labels.h"

namespace {

std::atomic<bool> g_stop{false};
securelink::BeaconClient* g_client = nullptr;

void on_signal(int) {
    g_stop.store(true);
    if (g_client) g_client->stop();
}

int derive_from_secret(const std::string& secret,
                       std::uint8_t key[SL_AEAD_KEY_LEN],
                       std::uint8_t iv [SL_AEAD_IV_LEN]) {
    const auto* s = reinterpret_cast<const std::uint8_t*>(secret.data());
    if (sl_hkdf_sha256(s, secret.size(),
                       nullptr, 0,
                       reinterpret_cast<const std::uint8_t*>(SL_KDF_LABEL_CLIENT_KEY),
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_CLIENT_KEY),
                       key, SL_AEAD_KEY_LEN) != 0) return -1;

    if (sl_hkdf_sha256(s, secret.size(),
                       nullptr, 0,
                       reinterpret_cast<const std::uint8_t*>(SL_KDF_LABEL_CLIENT_IV),
                       SL_KDF_LABEL_LEN(SL_KDF_LABEL_CLIENT_IV),
                       iv, SL_AEAD_IV_LEN) != 0) return -1;
    return 0;
}

void usage(const char* prog) {
    std::fprintf(stderr,
        "usage: %s [options]\n"
        "  --host=HOST          server address (default 127.0.0.1)\n"
        "  --port=PORT          server port (default 4443)\n"
        "  --secret=STRING      shared secret used to derive key/IV (required)\n"
        "  --client-id=HEX      16-char hex id; random if omitted\n"
        "  --interval=MS        beacon period in ms (default 5000)\n"
        "  --jitter=MS          +/- jitter applied per beacon (default 500)\n"
        "  --count=N            stop after N beacons (default: run forever)\n"
        "  --no-ack             do not request server ack\n"
        "  --verbose            extra logging\n",
        prog);
}

}  // namespace

int main(int argc, char** argv) try {
    securelink::CliArgs args(argc, argv,
        {"no-ack", "verbose", "help"});

    if (args.flag("help")) { usage(argv[0]); return 0; }

    const auto secret = args.get("secret");
    if (!secret) { usage(argv[0]); return 2; }

    securelink::BeaconClientConfig cfg;
    cfg.host        = args.get_string("host", "127.0.0.1");
    cfg.port        = static_cast<std::uint16_t>(args.get_int("port", 4443));
    cfg.interval_ms = args.get_u32("interval", 5000);
    cfg.jitter_ms   = args.get_u32("jitter", 500);
    cfg.request_ack = !args.flag("no-ack");

    if (auto id_hex = args.get("client-id")) {
        std::uint64_t parsed = 0;
        if (sl_id_from_hex(id_hex->c_str(), &parsed) != 0) {
            std::fprintf(stderr, "invalid --client-id (need 16 hex chars)\n");
            return 2;
        }
        cfg.client_id = parsed;
    } else {
        if (sl_id_random_u64(&cfg.client_id) != 0) {
            std::fprintf(stderr, "failed to generate client id\n");
            return 1;
        }
    }

    if (derive_from_secret(*secret, cfg.key, cfg.static_iv) != 0) {
        std::fprintf(stderr, "key derivation failed\n");
        return 1;
    }

    char id_hex[17];
    sl_id_to_hex(cfg.client_id, id_hex);
    std::fprintf(stderr, "beacon_cli: client_id=%s host=%s port=%u interval=%ums\n",
                 id_hex, cfg.host.c_str(), cfg.port, cfg.interval_ms);

    securelink::BeaconClient client(std::move(cfg));
    g_client = &client;
    std::signal(SIGINT,  on_signal);
    std::signal(SIGTERM, on_signal);

    if (!client.connect()) {
        std::fprintf(stderr, "connect failed\n");
        return 1;
    }

    const std::uint32_t count = args.get_u32("count", 0);
    if (count == 0) {
        client.run();
    } else {
        for (std::uint32_t i = 0; i < count && !g_stop.load(); ++i) {
            if (!client.send_one()) {
                std::fprintf(stderr, "send_one failed at i=%u\n", i);
                break;
            }
        }
    }

    const auto& s = client.stats();
    std::fprintf(stderr,
        "summary: sent=%lu acks=%lu fails=%lu reconnects=%lu last_rtt_ms=%lu\n",
        (unsigned long)s.beacons_sent, (unsigned long)s.acks_received,
        (unsigned long)s.send_failures, (unsigned long)s.reconnects,
        (unsigned long)s.last_rtt_ms);
    return 0;
} catch (const securelink::CliError& e) {
    std::fprintf(stderr, "arg error: %s\n", e.what());
    return 2;
} catch (const std::exception& e) {
    std::fprintf(stderr, "fatal: %s\n", e.what());
    return 1;
}
