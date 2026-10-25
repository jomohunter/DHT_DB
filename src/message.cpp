// message.cpp — binary serialization for the DHT wire protocol.
//
// Format recap (big-endian integers throughout):
//   [version:1][type:1][tx_id:4][sender contact][payload]
//   contact := [id:20][port:2][ip_len:1][ip:ip_len]
//
// Two design rules:
//   1. serialize() is trusted (our own messages), deserialize() is paranoid —
//      every length is checked against the remaining buffer before advancing.
//      A malformed datagram must yield nullopt, never a crash or a bad_alloc.
//   2. Small helpers (append16/append32, read16/read32) keep endianness
//      handling in exactly one place instead of scattered htons calls.

#include "dht/message.hpp"

#include <stdexcept>

namespace dht {
namespace {

// Bump when the wire format changes incompatibly. Peers with a different
// version silently drop each other's packets (see deserialize).
constexpr std::uint8_t WIRE_VERSION = 1;

// We refuse to build datagrams larger than this. UDP caps at 65507 bytes;
// staying under 1500 keeps us under typical MTU and avoids IP fragmentation,
// which for UDP means silent loss of any datagram that fragments.
constexpr std::size_t MAX_DATAGRAM_SIZE = 1400;

// ---------------------------------------------- write helpers (trusted) --

void append16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

void append32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 24));
    out.push_back(static_cast<std::uint8_t>(v >> 16));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v));
}

void appendContact(std::vector<std::uint8_t>& out, const Contact& c) {
    out.insert(out.end(), c.id.begin(), c.id.end());
    append16(out, c.port);
    if (c.ip.size() > 255) {
        throw std::invalid_argument("contact ip too long");
    }
    out.push_back(static_cast<std::uint8_t>(c.ip.size()));
    out.insert(out.end(), c.ip.begin(), c.ip.end());
}

// ------------------------------------------- read helpers (untrusted) --
// A cursor over the input; every read validates remaining length first.

struct Reader {
    const std::uint8_t* data;
    std::size_t len;
    std::size_t pos{0};

    bool remaining(std::size_t n) const { return len - pos >= n; }

    bool read8(std::uint8_t& v) {
        if (!remaining(1)) return false;
        v = data[pos++];
        return true;
    }

    bool read16(std::uint16_t& v) {
        if (!remaining(2)) return false;
        v = static_cast<std::uint16_t>(data[pos] << 8 | data[pos + 1]);
        pos += 2;
        return true;
    }

    bool read32(std::uint32_t& v) {
        if (!remaining(4)) return false;
        v = (static_cast<std::uint32_t>(data[pos]) << 24) |
            (static_cast<std::uint32_t>(data[pos + 1]) << 16) |
            (static_cast<std::uint32_t>(data[pos + 2]) << 8) |
            (static_cast<std::uint32_t>(data[pos + 3]));
        pos += 4;
        return true;
    }

    bool readBytes(std::uint8_t* dst, std::size_t n) {
        if (!remaining(n)) return false;
        std::copy(data + pos, data + pos + n, dst);
        pos += n;
        return true;
    }

    bool readString(std::string& out, std::size_t n) {
        if (!remaining(n)) return false;
        out.assign(reinterpret_cast<const char*>(data + pos), n);
        pos += n;
        return true;
    }
};

bool readContact(Reader& r, Contact& c) {
    if (!r.readBytes(c.id.data(), c.id.size())) return false;
    if (!r.read16(c.port)) return false;
    std::uint8_t ip_len = 0;
    if (!r.read8(ip_len)) return false;
    return r.readString(c.ip, ip_len);
}

} // namespace

// ---------------------------------------------------------- Message API --

bool Message::isResponse() const {
    switch (type) {
        case MessageType::Pong:
        case MessageType::Nodes:
        case MessageType::Value:
        case MessageType::Stored:
            return true;
        default:
            return false;
    }
}

std::vector<std::uint8_t> serialize(const Message& msg) {
    std::vector<std::uint8_t> out;
    out.reserve(64);

    out.push_back(WIRE_VERSION);
    out.push_back(static_cast<std::uint8_t>(msg.type));
    append32(out, msg.txId);
    appendContact(out, msg.sender);

    switch (msg.type) {
        case MessageType::Ping:
        case MessageType::Pong:
        case MessageType::Stored:
            break; // no payload
        case MessageType::FindNode:
        case MessageType::FindValue:
        case MessageType::Store:
            out.insert(out.end(), msg.target.begin(), msg.target.end());
            if (msg.type == MessageType::Store) {
                append16(out, static_cast<std::uint16_t>(msg.value.size()));
                out.insert(out.end(), msg.value.begin(), msg.value.end());
            }
            break;
        case MessageType::Value:
            append16(out, static_cast<std::uint16_t>(msg.value.size()));
            out.insert(out.end(), msg.value.begin(), msg.value.end());
            break;
        case MessageType::Nodes:
            if (msg.contacts.size() > K_BUCKET_SIZE) {
                throw std::invalid_argument("NODES response carries more than k contacts");
            }
            out.push_back(static_cast<std::uint8_t>(msg.contacts.size()));
            for (const auto& contact : msg.contacts) {
                appendContact(out, contact);
            }
            break;
    }

    if (out.size() > MAX_DATAGRAM_SIZE) {
        throw std::invalid_argument("message exceeds datagram size limit");
    }
    return out;
}

std::optional<Message> deserialize(const std::uint8_t* data, std::size_t len) {
    Reader r{data, len};
    Message msg;

    std::uint8_t version = 0, type = 0;
    if (!r.read8(version) || version != WIRE_VERSION) return std::nullopt;
    if (!r.read8(type) || type < static_cast<std::uint8_t>(MessageType::Ping) ||
        type > static_cast<std::uint8_t>(MessageType::Stored)) {
        return std::nullopt;
    }
    msg.type = static_cast<MessageType>(type);
    if (!r.read32(msg.txId)) return std::nullopt;
    if (!readContact(r, msg.sender)) return std::nullopt;

    switch (msg.type) {
        case MessageType::Ping:
        case MessageType::Pong:
        case MessageType::Stored:
            return msg;
        case MessageType::FindNode:
        case MessageType::FindValue:
            if (!r.readBytes(msg.target.data(), msg.target.size())) return std::nullopt;
            return msg;
        case MessageType::Store: {
            if (!r.readBytes(msg.target.data(), msg.target.size())) return std::nullopt;
            std::uint16_t value_len = 0;
            if (!r.read16(value_len)) return std::nullopt;
            if (!r.readString(msg.value, value_len)) return std::nullopt;
            return msg;
        }
        case MessageType::Value: {
            std::uint16_t value_len = 0;
            if (!r.read16(value_len)) return std::nullopt;
            if (!r.readString(msg.value, value_len)) return std::nullopt;
            return msg;
        }
        case MessageType::Nodes: {
            std::uint8_t count = 0;
            if (!r.read8(count)) return std::nullopt;
            if (count > K_BUCKET_SIZE) return std::nullopt; // protocol lie
            msg.contacts.reserve(count);
            for (std::uint8_t i = 0; i < count; ++i) {
                Contact c;
                if (!readContact(r, c)) return std::nullopt;
                msg.contacts.push_back(std::move(c));
            }
            return msg;
        }
    }
    return std::nullopt; // unreachable, guards future enum additions
}

} // namespace dht
