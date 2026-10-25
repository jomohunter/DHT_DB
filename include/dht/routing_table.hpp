// routing_table.hpp — Kademlia k-bucket routing table.
//
// The table is an array of 160 buckets. Bucket i stores contacts whose XOR
// distance to us has its most-significant set bit at position i, i.e. contacts
// at distance [2^i, 2^(i+1)). Consequences:
//   - bucket 0   -> our nearest neighbors (distance < 2)
//   - bucket 159 -> nodes on the opposite side of the ring
//   - bucket i fills up before bucket i+1 can ever be reached, so the table
//     automatically keeps "many far contacts, few near ones" — exactly the
//     routing structure that makes O(log n) lookups work.
//
// Within a bucket, contacts are kept least-recently-seen first. When a bucket
// is full, a new contact is only admitted after the least-recently-seen one
// fails a liveness check (handled by Node, not here).

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "dht/types.hpp"

namespace dht {

// A single k-bucket: a bounded list of contacts, ordered least-recently-seen
// first. Does not know its own index — the RoutingTable decides placement.
class KBucket {
public:
    // Insert or refresh a contact.
    // Returns true if the contact is now in the bucket (inserted or updated).
    // Returns false if the bucket is full and the contact is unknown — the
    // caller (Node) should then ping the least-recently-seen contact and evict
    // it if unresponsive.
    bool addOrUpdate(const Contact& contact);

    // Drop a contact (called after a failed ping or a goodbye message).
    bool remove(const NodeId& id);

    [[nodiscard]] const Contact* find(const NodeId& id) const;

    // Least-recently-seen contact, i.e. the eviction candidate. Empty bucket
    // yields nullopt.
    [[nodiscard]] std::optional<Contact> leastRecentlySeen() const;

    // Contacts in LRU order (least recent first).
    [[nodiscard]] const std::vector<Contact>& contacts() const;

    [[nodiscard]] std::size_t size() const;

private:
    std::vector<Contact> contacts_; // <= K_BUCKET_SIZE, LRU order
};

// The full routing table: one KBucket per bit of the ID space.
class RoutingTable {
public:
    explicit RoutingTable(NodeId self);

    // Add or refresh a contact. Returns false only when its bucket is full and
    // the contact is not already present (see KBucket::addOrUpdate).
    bool addOrUpdate(const Contact& contact);

    void remove(const NodeId& id);

    // The k closest known contacts to `target`, sorted by XOR distance
    // (closest first). This is the workhorse of iterative lookup.
    [[nodiscard]] std::vector<Contact> findClosest(const NodeId& target,
                                                   std::size_t k = K_BUCKET_SIZE) const;

    [[nodiscard]] const Contact* find(const NodeId& id) const;

    [[nodiscard]] std::size_t size() const; // total contacts across all buckets

    [[nodiscard]] const NodeId& selfId() const;

private:
    // Index of the bucket a given id belongs to: 159 minus the number of
    // leading zero bits in (self XOR id). Equivalent to "highest set bit".
    [[nodiscard]] std::size_t bucketIndex(const NodeId& id) const;

    NodeId self_;
    std::vector<KBucket> buckets_; // ID_BIT_LENGTH buckets
};

} // namespace dht
