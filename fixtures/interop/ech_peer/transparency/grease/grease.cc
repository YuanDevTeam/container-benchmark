// Bounded ECH GREASE consumer using the Core's already-built BoringSSL.
// This fixture runs only inside the owned Linux TUN client namespace.
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

namespace {
using Clock = std::chrono::steady_clock;
struct Socket {
  int value = -1;
  ~Socket() { if (value >= 0) close(value); }
};

void require(bool condition, const char* phase) {
  if (!condition) throw phase;
}

std::string hex(const unsigned char* bytes, size_t length) {
  static const char digits[] = "0123456789abcdef";
  std::string result(length * 2, '0');
  for (size_t i = 0; i < length; ++i) {
    result[i * 2] = digits[bytes[i] >> 4];
    result[i * 2 + 1] = digits[bytes[i] & 15];
  }
  return result;
}

std::string digest(const std::string& body) {
  std::array<unsigned char, SHA256_DIGEST_LENGTH> bytes{};
  require(SHA256(reinterpret_cast<const unsigned char*>(body.data()), body.size(),
                 bytes.data()) != nullptr, "digest");
  return hex(bytes.data(), bytes.size());
}

void wait(int fd, short events, Clock::time_point deadline) {
  for (;;) {
    auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - Clock::now()).count();
    require(remaining > 0, "deadline");
    pollfd descriptor{fd, events, 0};
    int result = poll(&descriptor, 1, static_cast<int>(std::min<int64_t>(remaining, INT_MAX)));
    if (result < 0 && errno == EINTR) continue;
    require(result > 0 && !(descriptor.revents & (POLLERR | POLLNVAL)), "poll");
    if (descriptor.revents & (events | POLLHUP)) return;
  }
}

void retry(SSL* ssl, int result, int fd, Clock::time_point deadline) {
  int error = SSL_get_error(ssl, result);
  require(error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE, "tls-io");
  wait(fd, error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, deadline);
}

std::string lower(std::string value) {
  for (char& ch : value) if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
  return value;
}

void verify_response(const std::string& response, const std::string& expected) {
  size_t split = response.find("\r\n\r\n");
  require(split != std::string::npos && split <= 4096, "response-head");
  require(response.compare(0, 17, "HTTP/1.1 200 OK\r\n") == 0, "response-status");
  bool length_seen = false, marker_seen = false;
  size_t cursor = response.find("\r\n") + 2;
  while (cursor < split) {
    size_t end = response.find("\r\n", cursor);
    require(end != std::string::npos && end <= split, "response-header");
    std::string line = response.substr(cursor, end - cursor);
    size_t colon = line.find(':');
    require(colon != std::string::npos && colon > 0, "response-header");
    std::string name = lower(line.substr(0, colon));
    std::string value = line.substr(colon + 1);
    size_t start = value.find_first_not_of(" \t"), last = value.find_last_not_of(" \t");
    value = start == std::string::npos ? "" : value.substr(start, last - start + 1);
    if (name == "content-length") {
      require(!length_seen && value == std::to_string(expected.size()), "response-length");
      length_seen = true;
    } else if (name == "x-transparency-response") {
      require(!marker_seen && value == "original", "response-marker");
      marker_seen = true;
    }
    require(name != "transfer-encoding", "response-framing");
    cursor = end + 2;
  }
  require(length_seen && marker_seen && response.substr(split + 4) == expected,
          "response-content");
}

int run(int argc, char** argv) {
  require(argc == 7, "arguments");
  const char* isolated = std::getenv("VOLE_INTEROP_ISOLATED");
  require(isolated && std::string(isolated) == "1", "isolation");
  std::string address = argv[1], port_text = argv[2], host = argv[3];
  std::string expected_pin = argv[5], id = argv[6];
  require(!port_text.empty() && port_text.size() <= 5 &&
          port_text.find_first_not_of("0123456789") == std::string::npos, "port");
  unsigned long port = std::stoul(port_text);
  require(port > 0 && port <= 65535, "port");
  require(!host.empty() && host.size() <= 253 &&
          host.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") == std::string::npos,
          "hostname");
  require(!id.empty() && id.size() <= 64 &&
          id.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == std::string::npos,
          "case-id");
  require(expected_pin.size() == 64 &&
          expected_pin.find_first_not_of("0123456789abcdef") == std::string::npos, "leaf-pin");

  sockaddr_storage destination{};
  auto* v4 = reinterpret_cast<sockaddr_in*>(&destination);
  auto* v6 = reinterpret_cast<sockaddr_in6*>(&destination);
  int family;
  socklen_t destination_size;
  if (inet_pton(AF_INET, address.c_str(), &v4->sin_addr) == 1) {
    family = AF_INET; destination_size = sizeof(*v4);
    v4->sin_family = AF_INET; v4->sin_port = htons(static_cast<uint16_t>(port));
  } else {
    require(inet_pton(AF_INET6, address.c_str(), &v6->sin6_addr) == 1, "address");
    family = AF_INET6; destination_size = sizeof(*v6);
    v6->sin6_family = AF_INET6; v6->sin6_port = htons(static_cast<uint16_t>(port));
  }
  Socket socket;
  socket.value = ::socket(family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  require(socket.value >= 0, "socket");
  auto deadline = Clock::now() + std::chrono::seconds(20);
  int connected = connect(socket.value, reinterpret_cast<sockaddr*>(&destination), destination_size);
  require(connected == 0 || errno == EINPROGRESS, "connect");
  if (connected != 0) {
    wait(socket.value, POLLOUT, deadline);
    int error = 0; socklen_t length = sizeof(error);
    require(getsockopt(socket.value, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && !error,
            "connect");
  }

  std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  require(ctx && SSL_CTX_load_verify_locations(ctx.get(), argv[4], nullptr) == 1 &&
          SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) == 1, "tls-context");
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
  const unsigned char protocols[] = {8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  require(ssl && SSL_set_fd(ssl.get(), socket.value) == 1 &&
          SSL_set_tlsext_host_name(ssl.get(), host.c_str()) == 1 &&
          SSL_set1_host(ssl.get(), host.c_str()) == 1 &&
          SSL_set_alpn_protos(ssl.get(), protocols, sizeof(protocols)) == 0, "tls-client");
  SSL_set_enable_ech_grease(ssl.get(), 1);
  for (;;) {
    int result = SSL_connect(ssl.get());
    if (result == 1) break;
    retry(ssl.get(), result, socket.value, deadline);
  }
  require(SSL_get_verify_result(ssl.get()) == X509_V_OK, "certificate");
  std::unique_ptr<X509, decltype(&X509_free)> certificate(SSL_get_peer_certificate(ssl.get()), X509_free);
  std::array<unsigned char, EVP_MAX_MD_SIZE> leaf{};
  unsigned int leaf_size = 0;
  require(certificate && X509_digest(certificate.get(), EVP_sha256(), leaf.data(), &leaf_size) == 1 &&
          hex(leaf.data(), leaf_size) == expected_pin, "leaf-pin");
  const unsigned char* selected = nullptr; unsigned int selected_size = 0;
  SSL_get0_alpn_selected(ssl.get(), &selected, &selected_size);
  require(selected && std::string(reinterpret_cast<const char*>(selected), selected_size) == "http/1.1", "alpn");

  const std::string body = "grease-original-request";
  const std::string expected = "original-response:" + body;
  std::string request = "POST /" + id + " HTTP/1.1\r\nHost: " + host + ":" + port_text +
      "\r\nX-Case-ID: " + id + "\r\nX-Transparency: original\r\nContent-Type: text/plain\r\nContent-Length: " +
      std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  size_t sent = 0;
  while (sent < request.size()) {
    require(Clock::now() < deadline, "deadline");
    int result = SSL_write(ssl.get(), request.data() + sent, static_cast<int>(request.size() - sent));
    if (result > 0) sent += static_cast<size_t>(result);
    else retry(ssl.get(), result, socket.value, deadline);
  }
  std::string response;
  std::array<char, 2048> buffer{};
  for (;;) {
    require(Clock::now() < deadline, "deadline");
    int result = SSL_read(ssl.get(), buffer.data(), buffer.size());
    if (result > 0) {
      require(response.size() + static_cast<size_t>(result) <= 8192, "response-bound");
      response.append(buffer.data(), static_cast<size_t>(result));
    } else {
      if (SSL_get_error(ssl.get(), result) == SSL_ERROR_ZERO_RETURN) break;
      retry(ssl.get(), result, socket.value, deadline);
    }
  }
  verify_response(response, expected);
  std::cout << "{\"id\":\"" << id << "\",\"status\":\"PASS\",\"grease_enabled\":true,"
      "\"certificate_verified\":true,\"leaf_pin_verified\":true,\"alpn\":\"http/1.1\","
      "\"leaf_sha256\":\"" << expected_pin << "\",\"request_sha256\":\"" << digest(body) <<
      "\",\"response_sha256\":\"" << digest(expected) << "\"}\n";
  return 0;
}
}  // namespace

int main(int argc, char** argv) {
  std::signal(SIGPIPE, SIG_IGN);
  try { return run(argc, argv); }
  catch (const char* phase) { std::cerr << "GREASE fixture phase=" << phase << '\n'; }
  catch (...) { std::cerr << "GREASE fixture phase=exception\n"; }
  return 1;
}
