#include "setup_code.h"

#include <mbedtls/ecp.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cstring>
#include <initializer_list>

#ifdef ESP_PLATFORM
#include <esp_random.h>
#else
#include <random>
#endif

namespace esphome::setup_code {

static constexpr uint32_t HANDSHAKE_TIMEOUT = 30000;  // ms from the device's share to the client's confirmation
static constexpr uint8_t FREE_ATTEMPTS = 3;
static constexpr uint32_t FIRST_COOLDOWN = 5000;  // ms, doubling with every further failed attempt
static constexpr uint32_t MAX_COOLDOWN = 60000;
static constexpr size_t TAG_SIZE = 16;
static constexpr char CONTEXT_PREFIX[] = "Improv Wi-Fi PAKE v1";

// RFC 9383's P-256 M and N, uncompressed
static constexpr uint8_t M[65] = {
    0x04, 0x88, 0x6e, 0x2f, 0x97, 0xac, 0xe4, 0x6e, 0x55, 0xba, 0x9d, 0xd7, 0x24, 0x25, 0x79, 0xf2, 0x99,
    0x3b, 0x64, 0xe1, 0x6e, 0xf3, 0xdc, 0xab, 0x95, 0xaf, 0xd4, 0x97, 0x33, 0x3d, 0x8f, 0xa1, 0x2f, 0x5f,
    0xf3, 0x55, 0x16, 0x3e, 0x43, 0xce, 0x22, 0x4e, 0x0b, 0x0e, 0x65, 0xff, 0x02, 0xac, 0x8e, 0x5c, 0x7b,
    0xe0, 0x94, 0x19, 0xc7, 0x85, 0xe0, 0xca, 0x54, 0x7d, 0x55, 0xa1, 0x2e, 0x2d, 0x20};
static constexpr uint8_t N[65] = {
    0x04, 0xd8, 0xbb, 0xd6, 0xc6, 0x39, 0xc6, 0x29, 0x37, 0xb0, 0x4d, 0x99, 0x7f, 0x38, 0xc3, 0x77, 0x07,
    0x19, 0xc6, 0x29, 0xd7, 0x01, 0x4d, 0x49, 0xa2, 0x4b, 0x4f, 0x98, 0xba, 0xa1, 0x29, 0x2b, 0x49, 0x07,
    0xd6, 0x0a, 0xa6, 0xbf, 0xad, 0xe4, 0x50, 0x08, 0xa6, 0x36, 0x33, 0x7f, 0x51, 0x68, 0xc6, 0x4d, 0x9b,
    0xd3, 0x60, 0x34, 0x80, 0x8c, 0xd5, 0x64, 0x49, 0x0b, 0x1e, 0x65, 0x6e, 0xdb, 0xe7};

static int random_bytes(void *, unsigned char *output, size_t size) {
#ifdef ESP_PLATFORM
  esp_fill_random(output, size);
#else
  static std::random_device device;
  for (size_t i = 0; i < size; i++)
    output[i] = static_cast<uint8_t>(device());
#endif
  return 0;
}

static bool equal_in_constant_time(std::span<const uint8_t> a, std::span<const uint8_t> b) {
  if (a.size() != b.size())
    return false;
  uint8_t difference = 0;
  for (size_t i = 0; i < a.size(); i++)
    difference |= a[i] ^ b[i];
  return difference == 0;
}

static void put_le32(std::vector<uint8_t> &out, uint32_t value) {
  for (int i = 0; i < 4; i++)
    out.push_back(static_cast<uint8_t>(value >> (8 * i)));
}

static uint32_t get_le32(const uint8_t *data) {
  return data[0] | data[1] << 8 | data[2] << 16 | static_cast<uint32_t>(data[3]) << 24;
}

/// Improv's result frame: command, data length, length-prefixed entries, then the sum of the previous bytes.
static std::vector<uint8_t> result_frame(uint8_t command, std::initializer_list<std::span<const uint8_t>> entries) {
  std::vector<uint8_t> frame{command, 0};
  for (auto entry : entries) {
    frame.push_back(static_cast<uint8_t>(entry.size()));
    frame.insert(frame.end(), entry.begin(), entry.end());
  }
  frame[1] = static_cast<uint8_t>(frame.size() - 2);
  uint8_t checksum = 0;
  for (uint8_t byte : frame)
    checksum += byte;
  frame.push_back(checksum);
  return frame;
}

/// RFC 9383's transcript item: an 8-byte little-endian length, then the bytes.
static void put_item(std::vector<uint8_t> &transcript, const uint8_t *data, size_t size) {
  for (int i = 0; i < 8; i++)
    transcript.push_back(static_cast<uint8_t>(static_cast<uint64_t>(size) >> (8 * i)));
  transcript.insert(transcript.end(), data, data + size);
}

Reply SetupCodeAuth::handle(uint8_t command, std::span<const uint8_t> data, uint32_t now) {
  Reply reply;
  switch (command) {
    case COMMAND_BEGIN: {
      this->end();  // aborts a handshake or session in progress
      if (this->failures_ > FREE_ATTEMPTS && now - this->failed_at_ < this->cooldown_()) {
        reply.error = ERROR_TOO_MANY_ATTEMPTS;
        return reply;
      }
      std::vector<uint8_t> iterations;
      put_le32(iterations, this->iterations_);
      reply.result = result_frame(COMMAND_BEGIN, {this->salt_, iterations});
      this->phase_ = Phase::BEGUN;
      return reply;
    }
    case COMMAND_SHARE: {
      Point share_v;
      std::array<uint8_t, 32> confirm_v;
      if (this->phase_ != Phase::BEGUN || data.size() != share_v.size() || !this->respond_(data, share_v, confirm_v))
        break;
      // the share lets the client test one guess offline: it counts as a failed attempt until confirmed
      if (this->failures_ < UINT8_MAX)
        this->failures_++;
      this->failed_at_ = this->shared_at_ = now;
      this->phase_ = Phase::SHARED;
      reply.result = result_frame(COMMAND_SHARE, {share_v, confirm_v});
      return reply;
    }
    case COMMAND_CONFIRM:
      if (this->phase_ != Phase::SHARED || now - this->shared_at_ > HANDSHAKE_TIMEOUT ||
          !equal_in_constant_time(data, this->confirm_p_))
        break;
      this->failures_ = 0;
      this->phase_ = Phase::SESSION;
      reply.result = result_frame(COMMAND_CONFIRM, {});
      return reply;
    case COMMAND_ENCRYPTED:
      if (this->phase_ != Phase::SESSION || !this->open_(data, reply.inner))
        break;
      return reply;
    default:
      break;
  }
  this->end();
  reply.error = ERROR_AUTHENTICATION_FAILED;
  return reply;
}

uint32_t SetupCodeAuth::cooldown_() const {
  uint8_t doublings = this->failures_ - FREE_ATTEMPTS - 1;
  return doublings >= 4 ? MAX_COOLDOWN : std::min(FIRST_COOLDOWN << doublings, MAX_COOLDOWN);
}

void SetupCodeAuth::end() {
  mbedtls_platform_zeroize(this->confirm_p_.data(), this->confirm_p_.size());
  mbedtls_platform_zeroize(this->shared_key_.data(), this->shared_key_.size());
  this->phase_ = Phase::IDLE;
  this->received_ = this->sent_ = 0;
  this->received_any_ = this->exhausted_ = false;
}

bool SetupCodeAuth::respond_(std::span<const uint8_t> share_p, Point &share_v, std::array<uint8_t, 32> &confirm_v) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point x, m, n, l, blinded_y, blinded_w0, unblinded, z, v;
  mbedtls_mpi w0, minus_w0, y, one;
  mbedtls_ecp_group_init(&group);
  for (auto *point : {&x, &m, &n, &l, &blinded_y, &blinded_w0, &unblinded, &z, &v})
    mbedtls_ecp_point_init(point);
  for (auto *mpi : {&w0, &minus_w0, &y, &one})
    mbedtls_mpi_init(mpi);

  uint8_t z_bytes[65], v_bytes[65];
  size_t length;
  // y*G and w0*N are each computed in constant time and only then added: mbedtls_ecp_muladd() is not constant time,
  // which is harmless with the public scalars 1 and 1
  bool ok =
      mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
      mbedtls_ecp_point_read_binary(&group, &x, share_p.data(), share_p.size()) == 0 &&
      mbedtls_ecp_check_pubkey(&group, &x) == 0 && mbedtls_ecp_point_read_binary(&group, &m, M, sizeof(M)) == 0 &&
      mbedtls_ecp_point_read_binary(&group, &n, N, sizeof(N)) == 0 &&
      mbedtls_ecp_point_read_binary(&group, &l, this->L_.data(), this->L_.size()) == 0 &&
      mbedtls_mpi_read_binary(&w0, this->w0_.data(), this->w0_.size()) == 0 &&
      mbedtls_mpi_sub_mpi(&minus_w0, &group.N, &w0) == 0 && mbedtls_mpi_lset(&one, 1) == 0 &&
      (this->test_y_ ? mbedtls_mpi_read_binary(&y, this->test_y_->data(), this->test_y_->size())
                     : mbedtls_ecp_gen_privkey(&group, &y, random_bytes, nullptr)) == 0 &&
      // shareV = y*G + w0*N
      mbedtls_ecp_mul(&group, &blinded_y, &y, &group.G, random_bytes, nullptr) == 0 &&
      mbedtls_ecp_mul(&group, &blinded_w0, &w0, &n, random_bytes, nullptr) == 0 &&
      mbedtls_ecp_muladd(&group, &blinded_y, &one, &blinded_y, &one, &blinded_w0) == 0 &&
      // Z = y*(shareP - w0*M), V = y*L
      mbedtls_ecp_mul(&group, &blinded_w0, &minus_w0, &m, random_bytes, nullptr) == 0 &&
      mbedtls_ecp_muladd(&group, &unblinded, &one, &x, &one, &blinded_w0) == 0 && !mbedtls_ecp_is_zero(&unblinded) &&
      mbedtls_ecp_mul(&group, &z, &y, &unblinded, random_bytes, nullptr) == 0 &&
      mbedtls_ecp_mul(&group, &v, &y, &l, random_bytes, nullptr) == 0 &&
      mbedtls_ecp_point_write_binary(&group, &blinded_y, MBEDTLS_ECP_PF_UNCOMPRESSED, &length, share_v.data(),
                                     share_v.size()) == 0 &&
      mbedtls_ecp_point_write_binary(&group, &z, MBEDTLS_ECP_PF_UNCOMPRESSED, &length, z_bytes, sizeof(z_bytes)) == 0 &&
      mbedtls_ecp_point_write_binary(&group, &v, MBEDTLS_ECP_PF_UNCOMPRESSED, &length, v_bytes, sizeof(v_bytes)) == 0;

  mbedtls_ecp_group_free(&group);
  for (auto *point : {&x, &m, &n, &l, &blinded_y, &blinded_w0, &unblinded, &z, &v})
    mbedtls_ecp_point_free(point);
  for (auto *mpi : {&w0, &minus_w0, &y, &one})
    mbedtls_mpi_free(mpi);
  if (!ok)
    return false;

  // Context = SHA-256("Improv Wi-Fi PAKE v1" || salt || iterations), then RFC 9383's transcript and key schedule
  std::vector<uint8_t> context_input(CONTEXT_PREFIX, CONTEXT_PREFIX + sizeof(CONTEXT_PREFIX) - 1);
  context_input.insert(context_input.end(), this->salt_.begin(), this->salt_.end());
  put_le32(context_input, this->iterations_);
  uint8_t context[32], main_key[32], confirmation_keys[64];
  mbedtls_sha256(context_input.data(), context_input.size(), context, 0);
  std::vector<uint8_t> transcript;
  put_item(transcript, context, sizeof(context));
  put_item(transcript, nullptr, 0);  // idProver
  put_item(transcript, nullptr, 0);  // idVerifier
  put_item(transcript, M, sizeof(M));
  put_item(transcript, N, sizeof(N));
  put_item(transcript, share_p.data(), share_p.size());
  put_item(transcript, share_v.data(), share_v.size());
  put_item(transcript, z_bytes, sizeof(z_bytes));
  put_item(transcript, v_bytes, sizeof(v_bytes));
  put_item(transcript, this->w0_.data(), this->w0_.size());
  mbedtls_sha256(transcript.data(), transcript.size(), main_key, 0);

  static constexpr char CONFIRMATION_KEYS[] = "ConfirmationKeys", SHARED_KEY[] = "SharedKey";
  const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  ok = mbedtls_hkdf(sha256, nullptr, 0, main_key, sizeof(main_key),
                    reinterpret_cast<const uint8_t *>(CONFIRMATION_KEYS), sizeof(CONFIRMATION_KEYS) - 1,
                    confirmation_keys, sizeof(confirmation_keys)) == 0 &&
       mbedtls_hkdf(sha256, nullptr, 0, main_key, sizeof(main_key), reinterpret_cast<const uint8_t *>(SHARED_KEY),
                    sizeof(SHARED_KEY) - 1, this->shared_key_.data(), this->shared_key_.size()) == 0 &&
       mbedtls_md_hmac(sha256, confirmation_keys, 32, share_v.data(), share_v.size(), this->confirm_p_.data()) == 0 &&
       mbedtls_md_hmac(sha256, confirmation_keys + 32, 32, share_p.data(), share_p.size(), confirm_v.data()) == 0;

  mbedtls_platform_zeroize(z_bytes, sizeof(z_bytes));
  mbedtls_platform_zeroize(v_bytes, sizeof(v_bytes));
  mbedtls_platform_zeroize(main_key, sizeof(main_key));
  mbedtls_platform_zeroize(confirmation_keys, sizeof(confirmation_keys));
  mbedtls_platform_zeroize(transcript.data(), transcript.size());
  return ok;
}

bool SetupCodeAuth::open_(std::span<const uint8_t> data, std::vector<uint8_t> &inner) {
  if (data.size() < 4 + 2 + TAG_SIZE)
    return false;
  uint32_t counter = get_le32(data.data());
  if (this->received_any_ && counter <= this->received_)
    return false;
  uint8_t nonce[12] = {};
  memcpy(nonce, data.data(), 4);
  const uint8_t aad[2] = {COMMAND_ENCRYPTED, 0x00};
  size_t size = data.size() - 4 - TAG_SIZE;
  inner.resize(size);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, this->shared_key_.data(), 128) == 0 &&
            mbedtls_gcm_auth_decrypt(&gcm, size, nonce, sizeof(nonce), aad, sizeof(aad), data.data() + 4 + size,
                                     TAG_SIZE, data.data() + 4, inner.data()) == 0;
  mbedtls_gcm_free(&gcm);
  // a frame without its checksum, and not another setup code command
  if (!ok || inner[1] != size - 2 || is_command(inner[0])) {
    mbedtls_platform_zeroize(inner.data(), inner.size());
    inner.clear();
    return false;
  }
  this->received_ = counter;
  this->received_any_ = true;
  return true;
}

std::vector<uint8_t> SetupCodeAuth::seal(std::span<const uint8_t> inner_result) {
  if (this->phase_ != Phase::SESSION || this->exhausted_ || 1 + 4 + inner_result.size() + TAG_SIZE > UINT8_MAX)
    return {};
  std::vector<uint8_t> entry;
  put_le32(entry, this->sent_);
  entry.resize(4 + inner_result.size() + TAG_SIZE);
  uint8_t nonce[12] = {};
  memcpy(nonce, entry.data(), 4);
  const uint8_t aad[2] = {COMMAND_ENCRYPTED, 0x01};
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  bool ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, this->shared_key_.data() + 16, 128) == 0 &&
            mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, inner_result.size(), nonce, sizeof(nonce), aad,
                                      sizeof(aad), inner_result.data(), entry.data() + 4, TAG_SIZE,
                                      entry.data() + 4 + inner_result.size()) == 0;
  mbedtls_gcm_free(&gcm);
  if (!ok)
    return {};
  // counters never wrap: a nonce is never used twice under one key
  this->exhausted_ = this->sent_ == UINT32_MAX;
  this->sent_++;
  return result_frame(COMMAND_ENCRYPTED, {entry});
}

}  // namespace esphome::setup_code
