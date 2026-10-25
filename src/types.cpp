// types.cpp — implementation of the ID-space helpers declared in types.hpp.
//
// The core of this file is SHA-1: the hash that maps arbitrary inputs (key
// strings, "ip:port" endpoints) into our 160-bit ID space. Two properties make
// it the right primitive for a DHT:
//
//   1. Uniformity (avalanche effect): a tiny input change flips ~half the output
//      bits. So IDs spread evenly across the 160-bit space and two similar keys
//      end up nowhere near each other — the XOR-distance topology stays balanced.
//
//   2. Preimage resistance: given a target ID, it's computationally infeasible
//      to find an input hashing to it. Without this, an attacker could grind
//      node IDs to position itself right next to specific keys (a "Sybil eclipse"
//      attack) and own the lookup paths. Hashing "ip:port" means the attacker
//      must also control its apparent network address to steer its ID.
//
// SHA-1 gives exactly 160 bits — one byte per bit of ID space, no truncation
// games. (For reference: IPFS uses SHA-256 truncated to 160; same idea.)
//
// The SHA-1 implementation below is the standard FIPS 180-1 algorithm, written
// out in full so the project has zero external dependencies.

#include "dht/types.hpp"

#include <cstdio>
#include <cstring>

namespace dht {
namespace {

// ------------------------------------------------------------------ SHA-1 --

// Left-rotate a 32-bit word. SHA-1 is built almost entirely from this op.
inline std::uint32_t rotl(std::uint32_t word, unsigned bits) {
    return (word << bits) | (word >> (32u - bits));
}

// Minimal streaming SHA-1: feed bytes with update(), then finalize() to get the
// 20-byte digest. Streaming (vs. one-shot) costs almost nothing and handles
// inputs of any length uniformly.
class Sha1 {
public:
    static constexpr std::size_t BLOCK_SIZE = 64;    // 512 bits
    static constexpr std::size_t DIGEST_SIZE = 20;   // 160 bits

    Sha1() { reset(); }

    void update(const std::uint8_t* data, std::size_t len) {
        total_bytes_ += len;
        for (std::size_t i = 0; i < len; ++i) {
            buffer_[buffer_len_++] = data[i];
            if (buffer_len_ == BLOCK_SIZE) { // buffer full -> absorb a block
                processBlock(buffer_.data());
                buffer_len_ = 0;
            }
        }
    }

    // Pad and produce the digest. Must be called exactly once per Sha1.
    void finalize(std::uint8_t out[DIGEST_SIZE]) {
        const std::uint64_t total_bits = total_bytes_ * 8;

        // Padding: 0x80, then zeros, then the original bit length as a 64-bit
        // big-endian integer — all so the final data is a whole number of
        // 512-bit blocks.
        buffer_[buffer_len_++] = 0x80;
        if (buffer_len_ > LENGTH_OFFSET) { // no room for the length field
            while (buffer_len_ < BLOCK_SIZE) buffer_[buffer_len_++] = 0;
            processBlock(buffer_.data());
            buffer_len_ = 0;
        }
        while (buffer_len_ < LENGTH_OFFSET) buffer_[buffer_len_++] = 0;
        for (int i = 7; i >= 0; --i) {
            buffer_[buffer_len_++] = static_cast<std::uint8_t>(total_bits >> (i * 8));
        }
        processBlock(buffer_.data());

        // Digest is just the five state words, big-endian.
        for (int w = 0; w < 5; ++w) {
            out[w * 4 + 0] = static_cast<std::uint8_t>(state_[w] >> 24);
            out[w * 4 + 1] = static_cast<std::uint8_t>(state_[w] >> 16);
            out[w * 4 + 2] = static_cast<std::uint8_t>(state_[w] >> 8);
            out[w * 4 + 3] = static_cast<std::uint8_t>(state_[w]);
        }
    }

private:
    static constexpr std::size_t LENGTH_OFFSET = 56; // bit length starts here

    void reset() {
        // FIPS 180-1 initial state.
        state_[0] = 0x67452301u;
        state_[1] = 0xEFCDAB89u;
        state_[2] = 0x98BADCFEu;
        state_[3] = 0x10325476u;
        state_[4] = 0xC3D2E1F0u;
        buffer_len_ = 0;
        total_bytes_ = 0;
    }

    // Mix one 512-bit block into the state.
    void processBlock(const std::uint8_t* block) {
        // 1) Expand 16 big-endian 32-bit words into 80.
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i) {
            w[i] = (static_cast<std::uint32_t>(block[i * 4 + 0]) << 24) |
                   (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
                   (static_cast<std::uint32_t>(block[i * 4 + 3]));
        }
        for (int i = 16; i < 80; ++i) {
            w[i] = rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        // 2) Eighty rounds of mixing.
        std::uint32_t a = state_[0], b = state_[1], c = state_[2],
                      d = state_[3], e = state_[4];
        for (int t = 0; t < 80; ++t) {
            std::uint32_t f, k;
            if (t < 20) {          // rounds 0-19:  choice function
                f = (b & c) | (~b & d);
                k = 0x5A827999u;
            } else if (t < 40) {   // rounds 20-39: parity
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
            } else if (t < 60) {   // rounds 40-59: majority
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
            } else {               // rounds 60-79: parity again
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
            }
            const std::uint32_t temp = rotl(a, 5) + f + e + k + w[t];
            e = d;
            d = c;
            c = rotl(b, 30);
            b = a;
            a = temp;
        }

        // 3) Fold the mixed block back into the state.
        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
    }

    std::uint32_t state_[5]{};
    std::array<std::uint8_t, BLOCK_SIZE> buffer_{}; // std::array so .data() works
    std::size_t buffer_len_{0};
    std::uint64_t total_bytes_{0};
};

// One-shot convenience over the streaming class.
NodeId sha1(const std::string& input) {
    Sha1 hasher;
    hasher.update(reinterpret_cast<const std::uint8_t*>(input.data()), input.size());
    NodeId out{};
    hasher.finalize(out.data());
    return out;
}

} // namespace

// ------------------------------------------------------------- public API --

NodeId xorDistance(const NodeId& a, const NodeId& b) {
    NodeId out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = a[i] ^ b[i];
    }
    return out;
}

int compareDistances(const NodeId& d1, const NodeId& d2) {
    // Byte 0 is the most significant, so a byte-wise memcmp is exactly an
    // unsigned 160-bit integer comparison. (std::array::compare would also
    // work, but it's C++20 and we target C++17.)
    return std::memcmp(d1.data(), d2.data(), d1.size());
}

Key keyFromString(const std::string& raw) {
    // Hashing (rather than "use the raw string as the key") is what guarantees
    // keys land uniformly in the 160-bit space regardless of their content.
    return sha1(raw);
}

NodeId nodeIdFromEndpoint(const std::string& ip, std::uint16_t port) {
    // The endpoint string is the node's public identity. Hashing it binds the
    // ID to the network address, so IDs can't be chosen freely.
    return sha1(ip + ":" + std::to_string(port));
}

std::string toHex(const NodeId& id) {
    std::string out;
    out.reserve(ID_BIT_LENGTH / 4); // 2 hex chars per byte = 40
    for (const std::uint8_t byte : id) {
        char hex[3];
        std::snprintf(hex, sizeof(hex), "%02x", byte);
        out += hex;
    }
    return out;
}

} // namespace dht
