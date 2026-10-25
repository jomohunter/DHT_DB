// transport.cpp — POSIX UDP socket implementation.
//
// The socket calls live here and nowhere else in the project:
//   socket() -> bind() -> { sendto() / poll() + recvfrom() } -> close()
//
// poll() gives us a receive timeout without threads: it sleeps until the
// socket is readable or the deadline passes, then recvfrom() drains exactly
// one datagram. This is the entire event-loop primitive the Node needs.

#include "dht/transport.hpp"

#include <stdexcept>

#include <arpa/inet.h>   // htons, htonl, inet_addr
#include <netinet/in.h>  // sockaddr_in
#include <poll.h>        // poll
#include <sys/socket.h>  // socket, bind, sendto, recvfrom
#include <unistd.h>      // close

namespace dht {
namespace {

// One sockaddr_in per endpoint, reconstituted on every send (cheap; keeps
// state out of the class).
sockaddr_in makeAddr(const std::string& ip, std::uint16_t port) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_addr(ip.c_str()) == INADDR_NONE) {
        throw std::invalid_argument("invalid IPv4 address: " + ip);
    }
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    return addr;
}

} // namespace

Transport::Transport(std::string ip, std::uint16_t port)
    : ip_(std::move(ip)), port_(port) {
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0); // UDP: no connect(), no streams
    if (fd_ < 0) {
        throw std::runtime_error("socket() failed");
    }

    sockaddr_in addr = makeAddr(ip_, port_);
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd_);
        throw std::runtime_error("bind() failed on " + ip_ + ":" +
                                 std::to_string(port_));
    }
}

Transport::~Transport() {
    if (fd_ >= 0) ::close(fd_);
}

bool Transport::send(const Message& msg, const std::string& ip, std::uint16_t port) {
    const auto bytes = serialize(msg);
    sockaddr_in addr = makeAddr(ip, port);

    const ssize_t sent =
        ::sendto(fd_, bytes.data(), bytes.size(), 0,
                 reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    return sent == static_cast<ssize_t>(bytes.size());
}

std::optional<Datagram> Transport::recv(int timeout_ms) {
    // poll() is a deadline-based sleep: it returns when a datagram arrives,
    // the timeout expires, or a signal interrupts. We only act on POLLIN.
    pollfd pfd{fd_, POLLIN, 0};
    const int ready = ::poll(&pfd, 1, timeout_ms);
    if (ready <= 0) return std::nullopt; // timeout or error -> caller retries

    // One recvfrom() == exactly one datagram (UDP preserves message bounds).
    // Buffer sized to the UDP payload ceiling; anything bigger is truncated.
    static constexpr std::size_t MAX_UDP = 65507;
    std::uint8_t buf[MAX_UDP];
    sockaddr_in from{};
    socklen_t from_len = sizeof(from);

    const ssize_t n = ::recvfrom(fd_, buf, sizeof(buf), 0,
                                 reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n <= 0) return std::nullopt;

    // Hostile input: deserialize() validates every length; garbage is dropped
    // and we loop so the caller still gets a real message or a clean timeout.
    auto msg = deserialize(buf, static_cast<std::size_t>(n));
    if (!msg) return std::nullopt;

    Datagram dgram;
    dgram.message = std::move(*msg);
    dgram.from_ip = inet_ntoa(from.sin_addr); // static buffer -> copied to string
    dgram.from_port = ntohs(from.sin_port);
    return dgram;
}

const std::string& Transport::ip() const { return ip_; }
std::uint16_t Transport::port() const { return port_; }

} // namespace dht
