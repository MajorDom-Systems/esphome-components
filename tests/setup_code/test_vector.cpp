// The device's side of setup code authentication against the complete test vector of improv-wifi/website#70 (dd868be),
// the vector majordom_esphome's client checks too: tests/setup_code/run.sh builds and runs it on the host.

#include "setup_code/setup_code.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

using namespace esphome::setup_code;

static std::vector<uint8_t> hex(const std::string &text) {
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i + 1 < text.size(); i += 2)
    bytes.push_back(static_cast<uint8_t>(std::stoi(text.substr(i, 2), nullptr, 16)));
  return bytes;
}

template<size_t S> static std::array<uint8_t, S> array(const std::string &text) {
  std::array<uint8_t, S> out{};
  auto bytes = hex(text);
  std::copy(bytes.begin(), bytes.end(), out.begin());
  return out;
}

static int failures = 0;

static void check(bool ok, const char *what) {
  printf("%s %s\n", ok ? "ok  " : "FAIL", what);
  failures += !ok;
}

static const std::string SALT = "5350414b453250204b65792053616c74";  // "SPAKE2P Key Salt"
static const std::string W0 = "b96170aae803346884724fe9a3b287c30330c2a660375d17bb205a8cf1aecb35";
static const std::string L =
    "0457f8ab79ee253ab6a8e46bb09e543ae422736de501e3db37d441fe344920d09548e4c18240630c4ff4913c53513839b7c07fcc0627a1b857"
    "3a149fcd1fa466cf";
static const std::string Y = "2222222222222222222222222222222222222222222222222222222222222222";
static const std::string SHARE_P =
    "044d0a606fb22bdb5f40f23a95bcd9b29346df87e0c4e18861366436d25d1c4e94963e021b443db17551776ad40f187ffcf89628f0bd52aafed2"
    "b271bad5d36398";
static const std::string SHARE_V =
    "040beae881fcc4f61d79db4e17948af82e83c5e72b829081e18783ad61877a53b082de3b1eee9bfd121aa865f38d9eeb590cd54762131b3361a5"
    "3cc2e7da2e9bf4";
static const std::string CONFIRM_P = "f54ad1b72b094316e3c749548fe7de4f0c226e326727c5dc7f70ec061fd9565b";
static const std::string CONFIRM_V = "419fef16b131f42390a5cc5963f55542636d4636dc4b5651e39b7d010325253e";
static const std::string WIFI_COMMAND = "011e0c4d79576972656c6573734150106d7973656375726570617373776f7264";
static const std::string SEALED_COMMAND =
    "000000003e74e15b97c8434bdb335e660f01f5da0caea34630586fdb20e245e9457703365d6dcbfc01c1b2fc285712a58ee227cf";
static const std::string WIFI_RESULT = "011413687474703a2f2f3139322e3136382e312e3130";
static const std::string SEALED_RESULT_FRAME =
    "0b2b2a00000000f4348f8cc0f9bce72cfe63b874e74529f099a9b5bdc64d9c2900c4cf23119100c2e2a144314ee9";

static SetupCodeAuth device() {
  SetupCodeAuth auth(hex(SALT), 1000, array<32>(W0), array<65>(L));
  auth.set_ephemeral_for_test(array<32>(Y));
  return auth;
}

int main() {
  auto auth = device();
  uint32_t now = 1000;

  auto begin = auth.handle(COMMAND_BEGIN, {}, now);
  check(begin.result == hex("081610" + SALT + "04e803000010"), "0x08 result: salt, iterations");

  auto share = auth.handle(COMMAND_SHARE, hex(SHARE_P), now);
  check(share.result == hex("096341" + SHARE_V + "20" + CONFIRM_V + "f8"), "0x09 result: shareV, confirmV");

  auto confirm = auth.handle(COMMAND_CONFIRM, hex(CONFIRM_P), now);
  check(confirm.error == ERROR_NONE && confirm.result == hex("0a000a") && auth.has_session(), "0x0A confirms");

  auto command = auth.handle(COMMAND_ENCRYPTED, hex(SEALED_COMMAND), now);
  check(command.error == ERROR_NONE && command.inner == hex(WIFI_COMMAND), "0x0B opens Send Wi-Fi settings");
  check(auth.seal(hex(WIFI_RESULT)) == hex(SEALED_RESULT_FRAME), "0x0B result sealed as in the vector");

  auto replay = auth.handle(COMMAND_ENCRYPTED, hex(SEALED_COMMAND), now);
  check(replay.error == ERROR_AUTHENTICATION_FAILED && !auth.has_session(), "a replayed packet ends the session");

  auth.handle(COMMAND_BEGIN, {}, now);
  auth.handle(COMMAND_SHARE, hex(SHARE_P), now);
  auto wrong = auth.handle(COMMAND_CONFIRM, hex(CONFIRM_V), now);
  check(wrong.error == ERROR_AUTHENTICATION_FAILED && wrong.result.empty() && !auth.has_session(),
        "a wrong confirmation is refused");
  check(auth.handle(COMMAND_ENCRYPTED, hex(SEALED_COMMAND), now).inner.empty(), "nothing opens without a session");

  auto out_of_order = device();
  check(out_of_order.handle(COMMAND_SHARE, hex(SHARE_P), now).error == ERROR_AUTHENTICATION_FAILED,
        "a share before 0x08 is refused");
  out_of_order.handle(COMMAND_BEGIN, {}, now);
  auto off_curve = hex(SHARE_P);
  off_curve[64] ^= 1;
  check(out_of_order.handle(COMMAND_SHARE, off_curve, now).error == ERROR_AUTHENTICATION_FAILED,
        "a share off the curve is refused");
  out_of_order.handle(COMMAND_BEGIN, {}, now);
  out_of_order.handle(COMMAND_SHARE, hex(SHARE_P), now);
  check(out_of_order.handle(COMMAND_CONFIRM, hex(CONFIRM_P), now + 30001).error == ERROR_AUTHENTICATION_FAILED,
        "a confirmation after 30 s is refused");

  auto guessing = device();  // three free attempts, then 5 s doubling up to 60 s; a success clears them
  for (int i = 0; i < 4; i++) {
    guessing.handle(COMMAND_BEGIN, {}, now);
    guessing.handle(COMMAND_SHARE, hex(SHARE_P), now);  // abandoned: still an attempt
  }
  check(guessing.handle(COMMAND_BEGIN, {}, now + 4999).error == ERROR_TOO_MANY_ATTEMPTS, "4 attempts: 5 s cooldown");
  check(guessing.handle(COMMAND_BEGIN, {}, now + 5000).error == ERROR_NONE, "and only 5 s");
  guessing.handle(COMMAND_SHARE, hex(SHARE_P), now + 5000);
  check(guessing.handle(COMMAND_BEGIN, {}, now + 14999).error == ERROR_TOO_MANY_ATTEMPTS, "5 attempts: 10 s");
  for (uint32_t i = 0; i < 10; i++) {  // a guess a minute
    guessing.handle(COMMAND_BEGIN, {}, now + 60000 * (i + 1));
    guessing.handle(COMMAND_SHARE, hex(SHARE_P), now + 60000 * (i + 1));
  }
  check(guessing.handle(COMMAND_BEGIN, {}, now + 659999).error == ERROR_TOO_MANY_ATTEMPTS, "capped at 60 s");
  check(guessing.handle(COMMAND_BEGIN, {}, now + 660000).error == ERROR_NONE, "never locked out");
  guessing.handle(COMMAND_SHARE, hex(SHARE_P), now + 660000);
  guessing.handle(COMMAND_CONFIRM, hex(CONFIRM_P), now + 660000);
  check(guessing.handle(COMMAND_BEGIN, {}, now + 660000).error == ERROR_NONE, "a success clears the attempts");

  auto random_y = SetupCodeAuth(hex(SALT), 1000, array<32>(W0), array<65>(L));
  random_y.handle(COMMAND_BEGIN, {}, now);
  auto fresh = random_y.handle(COMMAND_SHARE, hex(SHARE_P), now);
  check(fresh.error == ERROR_NONE && fresh.result != share.result, "a real handshake picks its own y");

  printf("%s\n", failures ? "FAILED" : "all passed");
  return failures ? EXIT_FAILURE : EXIT_SUCCESS;
}
