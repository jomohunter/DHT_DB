// node.hpp — the orchestrator. Owns the routing table, local storage, and
// transport; implements the RPC handlers and the iterative lookup algorithm.
//
// Protocol (all messages are UDP datagrams, request/response pairs):
//   PING        -> PONG         liveness check
//   FIND_NODE   -> NODES        "who are the k closest nodes to target?"
//   FIND_VALUE  -> VALUE|NODES  like FIND_NODE but answers with the value if held
//   STORE       -> STORED       "please persist (key, value)"
//
// A join is just: contact the bootstrap node, run an iterative FIND_NODE for
// our own ID (which discovers our neighborhood), then STORE our neighbors'
// data that now falls closest to us. Everything else composes from there.

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dht/routing_table.hpp"
#include "dht/types.hpp"

namespace dht {

class Storage;    // storage.hpp — local KV with TTL
class Transport;  // transport.hpp — UDP socket + serialization

class Node {
public:
    // `ip`/`port` is this node's advertised endpoint; it also determines the
    // node ID via nodeIdFromEndpoint.
    Node(std::string ip, std::uint16_t port);
    ~Node();

    // --- public API (what a client of this node calls) ---

    // Join an existing network through a known peer. No-op success if the
    // network is empty (we become the seed node).
    bool join(const std::string& bootstrapIp, std::uint16_t bootstrapPort);

    // Store a value under a key. Replicates onto the k closest nodes.
    bool put(const Key& key, const std::string& value);

    // Fetch a value. Runs an iterative FIND_VALUE; nullopt on miss.
    std::optional<std::string> get(const Key& key);

    // Process incoming datagrams forever (the node's event loop).
    void run();

    [[nodiscard]] const NodeId& id() const;

private:
    // --- RPC handlers (called by the transport callback on each request) ---
    // Each handler inspects the request message and sends back a response.
    // Message types arrive in transport.hpp; handlers are wired up in the .cpp.
    void handlePing(/* request */);
    void handleFindNode(/* request */);
    void handleFindValue(/* request */);
    void handleStore(/* request */);

    // --- iterative lookup (Kademlia's core algorithm) ---

    // Find the k closest nodes to `target` by querying alpha contacts per
    // round, converging on the target's neighborhood. Also refreshes the
    // routing table with everything learned along the way.
    std::vector<Contact> iterativeFindNode(const NodeId& target);

    // Same traversal, but stops early if a peer answers FIND_VALUE with the
    // value itself.
    std::optional<std::string> iterativeFindValue(const Key& key);

    // --- internals ---
    std::string ip_;
    std::uint16_t port_;
    NodeId id_;
    RoutingTable routing_table_;
    std::unique_ptr<Storage> storage_;
    std::unique_ptr<Transport> transport_;
};

} // namespace dht
