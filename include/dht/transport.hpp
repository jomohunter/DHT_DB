// transport.hpp — UDP socket wrapper. The only file that touches POSIX sockets.
//
// Deliberately dumb: it moves serialized Messages between endpoints and knows
// nothing about Kademlia, buckets, or storage. Three responsibilities:
//   1. own the socket (bind, close)
//   2. send:    Message + endpoint  -> one datagram
//   3. receive: wait with timeout   -> (Message, sender endpoint)
//
// Why UDP: a DHT is a sea of small request/response packets where a lost
// packet should just be retried, and connection setup per peer (TCP) would
// dwarf the payload. UDP also matches the protocol's semantics — a lookup
// asks many peers at once and uses whoever answers. The cost: datagrams can
// be lost or reordered. We handle that at the RPC layer (tx_id + timeouts),
// not here.
//
// Model: synchronous, single-threaded. recv() blocks up to a timeout. This
// keeps the event loop trivial to reason about; concurrency (alpha parallel
// lookups) is simulated by sending several requests before receiving.

#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "dht/message.hpp"
#include "dht/types.hpp"

namespace dht {

// A datagram plus where it came from. The sender's *claimed* endpoint is in
// msg.sender; the `endpoint` here is the actual socket source (trustworthy).
struct Datagram {
    Message message;
    std::string from_ip;
    std::uint16_t from_port{0};
};

class Transport {
public:
    // Bind a UDP socket to ip:port. Throws std::runtime_error on bind failure
    // (port in use, permission denied for ports < 1024, ...).
    Transport(std::string ip, std::uint16_t port);
    ~Transport();

    Transport(const Transport&) = delete;            // sockets are unique
    Transport& operator=(const Transport&) = delete;

    // Fire one datagram at endpoint. Returns false only on OS-level failure
    // (UDP "sends" to unreachable hosts still succeed — no feedback).
    bool send(const Message& msg, const std::string& ip, std::uint16_t port);

    // Wait up to timeout_ms for the next datagram. Returns nullopt on timeout
    // (also when timeout_ms == 0: pure poll). Malformed datagrams are dropped
    // and the wait continues — garbage from the network is never fatal.
    std::optional<Datagram> recv(int timeout_ms);

    [[nodiscard]] const std::string& ip() const;
    [[nodiscard]] std::uint16_t port() const;

private:
    std::string ip_;
    std::uint16_t port_;
    int fd_{-1}; // POSIX socket descriptor, -1 = closed
};

} // namespace dht
