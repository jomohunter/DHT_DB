// message.hpp — the DHT wire protocol: message model + binary serialization.
//
// Every RPC is a request/response pair of UDP datagrams. A `Message` is the
// in-memory model; serialize()/deserialize() convert between it and bytes.
// Keeping this apart from transport.hpp means we can unit-test the wire format
// without sockets, and swap the transport without touching serialization.
//
// Wire layout (all integers big-endian):
//   [version:1][type:1][tx_id:4]
//   [sender: contact]                  (20-byte id, 2-byte port, 1-byte ip len, ip)
//   [payload: type-dependent]
//
// The sender's endpoint rides in every message for one reason: UDP packets
// carry a source address, but on localhost behind NATs/proxies the advertised
// address can differ from the observed one. We trust the message payload (a
// simplification — real Kademlia verifies before trusting).

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include "dht/types.hpp"

namespace dht {

// The eight message kinds. Responses are distinct types (not just "reply"),
// so a handler can switch on the response type directly.
enum class MessageType : std::uint8_t {
    Ping = 1,     // request:  are you alive?
    Pong = 2,     // response: yes
    FindNode = 3, // request:  who are the k closest nodes to target?
    Nodes = 4,    // response: here are contacts
    FindValue = 5,// request:  do you have the value for key?
    Value = 6,    // response: yes, here it is
    Store = 7,    // request:  store this key/value
    Stored = 8,   // response: stored
};

struct Message {
    MessageType type{MessageType::Ping};
    // Transaction id: the requester picks one and the responder echoes it.
    // This is how a busy node matches up which response answers which request.
    std::uint32_t txId{0};
    Contact sender;             // who sent this (id + advertised endpoint)
    NodeId target{};            // FindNode/FindValue/Store: the key in question
    std::string value;          // Store request / Value response payload
    std::vector<Contact> contacts; // Nodes response payload

    [[nodiscard]] bool isResponse() const;
};

// Serialize a message to bytes. Throws std::invalid_argument if the message is
// too large for one datagram (> MAX_DATAGRAM_SIZE).
std::vector<std::uint8_t> serialize(const Message& msg);

// Parse bytes into a Message. Returns nullopt on any malformation — input from
// the network is hostile, so every length field is bounds-checked before use.
// `bytes` may contain a trailing datagram suffix; extra bytes are ignored.
std::optional<Message> deserialize(const std::uint8_t* data, std::size_t len);

} // namespace dht
