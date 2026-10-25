// types.hpp — foundational value types and constants shared across the DHT.
//
// Every participant in the network (node or key) is a 160-bit identifier.
// Kademlia measures "closeness" between two IDs with XOR: distance(a, b) = a XOR b.
// The bucket a contact belongs to is determined by the position of the highest
// set bit of that XOR (see RoutingTable::bucketIndex).

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace dht {

// 160-bit identifier, same size as SHA-1. Nodes derive their ID from a hash of
// their IP:port; keys are hashed from the raw key string. Same ID space for both
// is what lets us say "key K lives at the node closest to K".
using NodeId = std::array<uint8_t, 20>;

// Keys live in the same space as node IDs.
using Key = NodeId;

// One known peer. Shared vocabulary: routing logic manipulates contacts,
// transport logic turns them into socket addresses. POD-ish on purpose.
struct Contact {
    NodeId id{};
    std::string ip;
    std::uint16_t port{0};

    bool operator==(const Contact& other) const { return id == other.id; }
};

// k: max contacts per k-bucket, and the replication factor (value stored on the
// k closest nodes to a key). 8 is small for a real network but keeps localhost
// experiments easy to reason about.
constexpr std::size_t K_BUCKET_SIZE = 8;

// alpha: lookup concurrency. A lookup queries this many closest contacts in
// parallel per round. 3 is the classic Kademlia value.
constexpr std::size_t LOOKUP_CONCURRENCY = 3;

// Bit-length of the ID space. Also the number of k-buckets per routing table.
constexpr std::size_t ID_BIT_LENGTH = 160;

// Kademlia's distance metric: distance(a, b) = a XOR b, treated as a 160-bit
// unsigned big-endian integer (byte 0 is most significant). This is the only
// notion of "near" the DHT has.
NodeId xorDistance(const NodeId& a, const NodeId& b);

// Compare two distances numerically (they're big-endian byte arrays, so plain
// lexicographic comparison on bytes == unsigned integer comparison).
// Returns <0, 0, >0 like memcmp.
int compareDistances(const NodeId& d1, const NodeId& d2);

// Hash a raw key string into the 160-bit key space (SHA-1).
Key keyFromString(const std::string& raw);

// Derive a node ID from its network endpoint (hash of "ip:port").
NodeId nodeIdFromEndpoint(const std::string& ip, std::uint16_t port);

// Hex rendering, for logs and debugging.
std::string toHex(const NodeId& id);

} // namespace dht
