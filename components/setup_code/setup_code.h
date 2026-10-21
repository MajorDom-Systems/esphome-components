#pragma once

// Setup code authentication, as proposed for Improv via BLE revision 2.5 (improv-wifi/website#70, at dd868be): the
// device keeps a SPAKE2+ verifier (RFC 9383, P-256, derived from the code as Matter derives its own), a controller
// proves it knows the code, and every command then travels sealed (AES-128-GCM) in an Encrypted RPC frame.
// Plain C++ on mbedTLS, without ESPHome: tests/setup_code checks it against the RFC's test vector on the host.

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace esphome::setup_code {

enum Command : uint8_t {
  COMMAND_BEGIN = 0x08,
  COMMAND_SHARE = 0x09,
  COMMAND_CONFIRM = 0x0A,
  COMMAND_ENCRYPTED = 0x0B,
};

enum Error : uint8_t {
  ERROR_NONE = 0x00,
  ERROR_AUTHENTICATION_FAILED = 0x06,
  ERROR_TOO_MANY_ATTEMPTS = 0x07,
};

static constexpr uint8_t CAPABILITY = 1 << 4;  // of the Capabilities characteristic and the service data

inline bool is_command(uint8_t command) { return command >= COMMAND_BEGIN && command <= COMMAND_ENCRYPTED; }

/// What a command did: a result frame to notify, an error to report, and for an Encrypted RPC the inner command opened
/// (command, length, data: a frame without its checksum).
struct Reply {
  Error error{ERROR_NONE};
  std::vector<uint8_t> result;
  std::vector<uint8_t> inner;
};

class SetupCodeAuth {
 public:
  using Scalar = std::array<uint8_t, 32>;
  using Point = std::array<uint8_t, 65>;  // uncompressed SEC1

  SetupCodeAuth(std::vector<uint8_t> salt, uint32_t iterations, const Scalar &w0, const Point &L)
      : salt_(std::move(salt)), iterations_(iterations), w0_(w0), L_(L) {}
  ~SetupCodeAuth() { this->end(); }

  /// Handles a setup code command (`is_command`) whose frame checked out; ``now`` in ms.
  Reply handle(uint8_t command, std::span<const uint8_t> data, uint32_t now);
  /// The Encrypted RPC result frame for an inner result (command, length, entries); empty without a session.
  std::vector<uint8_t> seal(std::span<const uint8_t> inner_result);
  bool has_session() const { return this->phase_ == Phase::SESSION; }
  /// Forgets the handshake or session (disconnect, authorization timeout, provisioned).
  void end();

  void set_ephemeral_for_test(const Scalar &y) { this->test_y_ = y; }  // the RFC vector's fixed y

 protected:
  enum class Phase : uint8_t { IDLE, BEGUN, SHARED, SESSION };

  bool respond_(std::span<const uint8_t> share_p, Point &share_v, std::array<uint8_t, 32> &confirm_v);
  bool open_(std::span<const uint8_t> data, std::vector<uint8_t> &inner);
  uint32_t cooldown_() const;

  std::vector<uint8_t> salt_;
  uint32_t iterations_;
  Scalar w0_;
  Point L_;

  Phase phase_{Phase::IDLE};
  uint32_t shared_at_{0};
  uint32_t failed_at_{0};
  uint8_t failures_{0};  // handshakes that got the device's share but did not confirm
  std::array<uint8_t, 32> confirm_p_{};
  std::array<uint8_t, 32> shared_key_{};  // client-to-device AES key, then device-to-client
  uint32_t received_{0};
  bool received_any_{false};
  uint32_t sent_{0};
  bool exhausted_{false};
  std::optional<Scalar> test_y_;
};

}  // namespace esphome::setup_code
