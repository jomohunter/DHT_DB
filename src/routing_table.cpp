// routing_table.cpp — k-bucket placement, LRU policy, and closest-contact search.
//
// Two pieces of math drive everything here:
//
//   1. bucketIndex(id) = position of the highest set bit of (self XOR id).
//      "Position" counts from the least-significant bit, so the index is the
//      integer i where distance ∈ [2^i, 2^(i+1)). This single formula is what
//      turns a flat set of peers into Kademlia's exponentially-spaced rings.
//
//   2. findClosest(target) = the k smallest distances, where distance is XOR
//      interpreted as a big-endian integer. Since NodeId byte 0 is the most
//      significant, std::array's lexicographic compare == numeric compare, and
//      the classic "XOR then compare" ordering falls out for free.

#include "dht/routing_table.hpp"

#include <algorithm>

namespace dht {

// --------------------------------------------------------------- KBucket --

bool KBucket::addOrUpdate(const Contact& contact) {
    // Already known? Refresh: update its address and move it to the back
    // (most-recently-seen). Recency is the whole eviction policy.
    if (auto it = std::find(contacts_.begin(), contacts_.end(), contact);
        it != contacts_.end()) {
        *it = contact;
        if (it != contacts_.end() - 1) {
            std::rotate(it, it + 1, contacts_.end());
        }
        return true;
    }

    // Unknown and the bucket is full: refuse. The caller (Node) decides
    // whether the least-recently-seen contact is dead and can be evicted.
    if (contacts_.size() >= K_BUCKET_SIZE) {
        return false;
    }

    contacts_.push_back(contact); // newest goes to the back
    return true;
}

bool KBucket::remove(const NodeId& id) {
    // Linear scan is deliberate: k is tiny (8), so an index would be pure
    // overhead. Complexity of every operation here is O(k), not O(n).
    for (auto it = contacts_.begin(); it != contacts_.end(); ++it) {
        if (it->id == id) {
            contacts_.erase(it);
            return true;
        }
    }
    return false;
}

const Contact* KBucket::find(const NodeId& id) const {
    for (const auto& contact : contacts_) {
        if (contact.id == id) return &contact;
    }
    return nullptr;
}

std::optional<Contact> KBucket::leastRecentlySeen() const {
    if (contacts_.empty()) return std::nullopt;
    return contacts_.front(); // front = least recently seen (LRU order)
}

const std::vector<Contact>& KBucket::contacts() const {
    return contacts_;
}

std::size_t KBucket::size() const {
    return contacts_.size();
}

// ---------------------------------------------------------- RoutingTable --

RoutingTable::RoutingTable(NodeId self)
    : self_(self), buckets_(ID_BIT_LENGTH) {
    // One empty KBucket per bit of the ID space: 160 of them.
}

bool RoutingTable::addOrUpdate(const Contact& contact) {
    // Never store ourselves — we're not our own peer.
    if (contact.id == self_) return true;

    return buckets_[bucketIndex(contact.id)].addOrUpdate(contact);
}

void RoutingTable::remove(const NodeId& id) {
    buckets_[bucketIndex(id)].remove(id);
}

const Contact* RoutingTable::find(const NodeId& id) const {
    return buckets_[bucketIndex(id)].find(id);
}

std::vector<Contact> RoutingTable::findClosest(const NodeId& target,
                                               std::size_t k) const {
    // Gather every contact, then keep the k smallest XOR distances to target.
    // Real Kademlia prunes per bucket while scanning; with a local table of at
    // most 160*8 contacts, gather-then-sort is simpler and just as correct.
    std::vector<Contact> all;
    all.reserve(size());
    for (const auto& bucket : buckets_) {
        const auto& contacts = bucket.contacts();
        all.insert(all.end(), contacts.begin(), contacts.end());
    }

    std::sort(all.begin(), all.end(),
              [&target](const Contact& a, const Contact& b) {
                  return compareDistances(xorDistance(a.id, target),
                                          xorDistance(b.id, target)) < 0;
              });

    if (all.size() > k) {
        all.resize(k);
    }
    return all;
}

std::size_t RoutingTable::size() const {
    std::size_t total = 0;
    for (const auto& bucket : buckets_) {
        total += bucket.size();
    }
    return total;
}

const NodeId& RoutingTable::selfId() const {
    return self_;
}

std::size_t RoutingTable::bucketIndex(const NodeId& id) const {
    const NodeId distance = xorDistance(self_, id);

    // Find the most-significant nonzero byte. Byte 0 is most significant, so
    // the first hit contains the highest set bit of the whole distance.
    for (std::size_t byte = 0; byte < distance.size(); ++byte) {
        if (distance[byte] == 0) continue;

        // Bits of this byte occupy positions [(19-byte)*8, (19-byte)*8 + 7].
        // Within the byte, index of the highest set bit is floor(log2(v)),
        // computed here with a plain loop for clarity.
        std::uint8_t v = distance[byte];
        std::size_t bit_in_byte = 0;
        while (v >>= 1) {
            ++bit_in_byte;
        }
        return (distance.size() - 1 - byte) * 8 + bit_in_byte;
    }

    // distance == 0 means id == self_, which addOrUpdate filters out before we
    // ever get here. Bucket 0 is harmless if it slips through.
    return 0;
}

} // namespace dht
