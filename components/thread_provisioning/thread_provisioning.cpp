#include "thread_provisioning.h"

#if defined(USE_ESP32) && defined(USE_OPENTHREAD)

#include "esphome/components/bytebuffer/bytebuffer.h"
#include "esphome/components/esp32_ble/ble.h"
#include "esphome/components/esp32_ble_server/ble_2902.h"
#include "esphome/components/openthread/openthread.h"
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"

#include <openthread/ip6.h>
#include <openthread/thread.h>

#include <algorithm>
#include <cstring>

#include "sdkconfig.h"

namespace esphome::thread_provisioning {

using namespace esp32_ble_server;
using bytebuffer::ByteBuffer;
using openthread::InstanceLock;

static const char *const TAG = "thread_provisioning";
static constexpr uint32_t STOP_DELAY = 10000;  // ms: lets the client read the final state before the service goes

// The dataset carries the network key: never logged, and wiped from every buffer of ours once used
static void wipe(void *data, size_t size) {
  volatile uint8_t *p = static_cast<volatile uint8_t *>(data);
  while (size--)
    *p++ = 0;
}

static void wipe(std::vector<uint8_t> &data) {
  wipe(data.data(), data.size());
  data.clear();
}

// Unprovisioned = the active dataset still has the placeholder key the image was built with (`openthread: network_key:`)
static bool is_placeholder(const otNetworkKey &key) {
  uint8_t placeholder[OT_NETWORK_KEY_SIZE];
  parse_hex(CONFIG_OPENTHREAD_NETWORK_MASTERKEY, sizeof(CONFIG_OPENTHREAD_NETWORK_MASTERKEY) - 1, placeholder,
            sizeof(placeholder));
  return memcmp(key.m8, placeholder, OT_NETWORK_KEY_SIZE) == 0;
}

void ThreadProvisioning::setup() {
#ifdef USE_BINARY_SENSOR
  if (this->authorizer_ != nullptr) {
    this->authorizer_->add_on_state_callback([this](bool state) {
      if (state)
        this->authorized_start_ = millis();
    });
  }
#endif
  global_ble_server->on_disconnect([this](uint16_t) { wipe(this->incoming_); });
}

void ThreadProvisioning::loop() {
  switch (this->phase_) {
    case Phase::CHECKING:
      this->check_dataset_();
      break;
    case Phase::STARTING:
      this->keep_thread_off_();
      this->start_service_();
      break;
    case Phase::SERVING:
      this->keep_thread_off_();
      this->serve_();
      break;
    case Phase::ATTACHING:
      this->check_attached_();
      break;
    case Phase::DONE:
      break;
  }
}

void ThreadProvisioning::check_dataset_() {
  auto *ot = openthread::global_openthread_component;
  if (ot == nullptr || !ot->is_lock_initialized())
    return;
  InstanceLock lock = InstanceLock::try_acquire(10);
  if (!lock)
    return;
  otInstance *instance = lock.get_instance();
  otOperationalDataset active;
  if (otDatasetGetActive(instance, &active) != OT_ERROR_NONE)
    return;  // the openthread component has not committed a dataset yet
  bool unprovisioned = is_placeholder(active.mNetworkKey);
  wipe(&active, sizeof(active));
  if (!unprovisioned) {
    ESP_LOGI(TAG, "Thread network provisioned: BLE provisioning stays off");
    this->phase_ = Phase::DONE;
    this->disable_loop();
    return;
  }
  otDatasetGetActiveTlvs(instance, &this->placeholder_);
  otThreadSetEnabled(instance, false);
  ESP_LOGI(TAG, "No Thread network yet: Thread stays off until a dataset is given over BLE");
  this->phase_ = Phase::STARTING;
}

// The openthread component starts Thread on its own task, possibly after check_dataset_(): the placeholder network is
// never meant to be joined (or formed), so Thread is kept off while the node waits
void ThreadProvisioning::keep_thread_off_() {
  InstanceLock lock = InstanceLock::try_acquire(0);
  if (lock && otThreadGetDeviceRole(lock.get_instance()) != OT_DEVICE_ROLE_DISABLED)
    otThreadSetEnabled(lock.get_instance(), false);
}

void ThreadProvisioning::start_service_() {
  if (!global_ble_server->is_running())
    return;
  if (this->service_ == nullptr) {
    this->service_ = global_ble_server->create_service(ESPBTUUID::from_raw(SERVICE_UUID), true);
    this->state_char_ = this->service_->create_characteristic(
        STATE_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    this->state_char_->add_descriptor(new BLE2902());
    this->error_char_ = this->service_->create_characteristic(
        ERROR_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    this->error_char_->add_descriptor(new BLE2902());
    this->rpc_char_ = this->service_->create_characteristic(RPC_UUID, BLECharacteristic::PROPERTY_WRITE);
    this->rpc_char_->on_write([this](std::span<const uint8_t> data, uint16_t) {
      this->incoming_.insert(this->incoming_.end(), data.begin(), data.end());
    });
    this->result_char_ = this->service_->create_characteristic(
        RESULT_UUID, BLECharacteristic::PROPERTY_READ | BLECharacteristic::PROPERTY_NOTIFY);
    this->result_char_->add_descriptor(new BLE2902());
    this->error_char_->set_value(ByteBuffer::wrap(static_cast<uint8_t>(ERROR_NONE)));
  }
  if (this->service_->is_created()) {
    this->service_->start();
    return;
  }
  if (!this->service_->is_running())
    return;
  this->set_state_(this->authorized_() ? STATE_AUTHORIZED : STATE_AWAITING_AUTHORIZATION);
  esp32_ble::global_ble->advertising_start();
  this->advertising_ = true;
  ESP_LOGI(TAG, "Advertising the Thread provisioning service");
  this->phase_ = Phase::SERVING;
}

bool ThreadProvisioning::authorized_() const {
#ifdef USE_BINARY_SENSOR
  if (this->authorizer_ != nullptr)
    return this->authorized_start_ != 0 && millis() - this->authorized_start_ < this->authorized_duration_;
#endif
  return true;
}

void ThreadProvisioning::serve_() {
  if (this->state_ == STATE_AWAITING_AUTHORIZATION && this->authorized_()) {
    this->set_state_(STATE_AUTHORIZED);
  } else if (this->state_ == STATE_AUTHORIZED && !this->authorized_()) {
    ESP_LOGD(TAG, "Authorization expired");
    this->set_state_(STATE_AWAITING_AUTHORIZATION);
  }
  if (!this->incoming_.empty())
    this->process_incoming_();
}

void ThreadProvisioning::process_incoming_() {
  if (this->incoming_.size() < 3)
    return;
  size_t length = this->incoming_[1];
  if (this->incoming_.size() < length + 3)
    return;  // more chunks to come
  if (this->incoming_.size() > length + 3) {
    ESP_LOGW(TAG, "Malformed command");
    this->set_error_(ERROR_INVALID_RPC);
    wipe(this->incoming_);
    return;
  }
  uint8_t checksum = 0;
  for (size_t i = 0; i < length + 2; i++)
    checksum += this->incoming_[i];
  if (checksum != this->incoming_[length + 2]) {
    ESP_LOGW(TAG, "Bad checksum");
    this->set_error_(ERROR_INVALID_RPC);
  } else if (this->incoming_[0] != COMMAND_SET_DATASET) {
    ESP_LOGW(TAG, "Unknown command 0x%02X", this->incoming_[0]);
    this->set_error_(ERROR_UNKNOWN_RPC);
  } else if (this->state_ != STATE_AUTHORIZED) {
    ESP_LOGW(TAG, "Dataset received, but not authorized");
    this->set_error_(ERROR_NOT_AUTHORIZED);
  } else {
    this->set_error_(ERROR_NONE);
    this->apply_dataset_(std::span<const uint8_t>(this->incoming_.data() + 2, length));
  }
  wipe(this->incoming_);
}

void ThreadProvisioning::apply_dataset_(std::span<const uint8_t> data) {
  otOperationalDatasetTlvs tlvs{};
  otOperationalDataset dataset{};
  if (data.size() > sizeof(tlvs.mTlvs)) {
    this->set_error_(ERROR_INVALID_DATASET);
    return;
  }
  memcpy(tlvs.mTlvs, data.data(), data.size());
  tlvs.mLength = data.size();
  InstanceLock lock = InstanceLock::acquire();
  otInstance *instance = lock.get_instance();
  const auto &has = dataset.mComponents;
  bool valid = otDatasetParseTlvs(&tlvs, &dataset) == OT_ERROR_NONE && has.mIsActiveTimestampPresent &&
               has.mIsNetworkKeyPresent && has.mIsExtendedPanIdPresent && has.mIsPanIdPresent &&
               has.mIsChannelPresent && has.mIsMeshLocalPrefixPresent && !is_placeholder(dataset.mNetworkKey);
  if (!valid) {
    ESP_LOGW(TAG, "Rejected an incomplete Thread dataset");
    this->set_error_(ERROR_INVALID_DATASET);
  } else if (otDatasetSetActiveTlvs(instance, &tlvs) != OT_ERROR_NONE || otIp6SetEnabled(instance, true) != OT_ERROR_NONE ||
             otThreadSetEnabled(instance, true) != OT_ERROR_NONE) {
    ESP_LOGE(TAG, "OpenThread refused the dataset");
    this->set_error_(ERROR_UNKNOWN);
  } else {
    ESP_LOGI(TAG, "Joining Thread network '%s' on channel %u", dataset.mNetworkName.m8, dataset.mChannel);
    this->attach_start_ = millis();
    this->set_state_(STATE_ATTACHING);
    this->phase_ = Phase::ATTACHING;
  }
  wipe(&tlvs, sizeof(tlvs));
  wipe(&dataset, sizeof(dataset));
}

void ThreadProvisioning::check_attached_() {
  InstanceLock lock = InstanceLock::try_acquire(0);
  if (!lock)
    return;
  otInstance *instance = lock.get_instance();
  otDeviceRole role = otThreadGetDeviceRole(instance);
  // a leader formed a partition of its own: it did not find the network, so it is not attached
  if (role == OT_DEVICE_ROLE_CHILD || role == OT_DEVICE_ROLE_ROUTER) {
    ESP_LOGI(TAG, "Attached to the Thread network as %s", otThreadDeviceRoleToString(role));
    wipe(&this->placeholder_, sizeof(this->placeholder_));
    this->set_state_(STATE_ATTACHED);
    const uint8_t result[] = {COMMAND_SET_DATASET, 0, COMMAND_SET_DATASET};  // no data; checksum = 0x01 + 0x00
    this->result_char_->set_value(std::vector<uint8_t>(result, result + sizeof(result)));
    this->result_char_->notify();
    this->phase_ = Phase::DONE;
    this->set_timeout("stop", STOP_DELAY, [this] {
      if (this->advertising_)
        esp32_ble::global_ble->advertising_stop();
      this->advertising_ = false;
      this->service_->stop();
      this->disable_loop();
      ESP_LOGI(TAG, "Thread provisioning service stopped");
    });
    return;
  }
  if (millis() - this->attach_start_ < this->attach_timeout_)
    return;
  // back to unprovisioned, so the node can be given another dataset instead of being stuck on one it cannot join
  ESP_LOGW(TAG, "Could not attach within %" PRIu32 " s: back to waiting for a dataset", this->attach_timeout_ / 1000);
  otThreadSetEnabled(instance, false);
  otDatasetSetActiveTlvs(instance, &this->placeholder_);
  this->set_error_(ERROR_UNABLE_TO_ATTACH);
#ifdef USE_BINARY_SENSOR
  if (this->authorizer_ != nullptr)
    this->authorized_start_ = millis();  // like Improv: the user just authorized this attempt
#endif
  this->set_state_(STATE_AUTHORIZED);
  this->phase_ = Phase::SERVING;
}

void ThreadProvisioning::set_state_(State state) {
  ESP_LOGD(TAG, "State 0x%02X -> 0x%02X", this->state_, state);
  this->state_ = state;
  this->state_char_->set_value(ByteBuffer::wrap(static_cast<uint8_t>(state)));
  this->state_char_->notify();
}

void ThreadProvisioning::set_error_(Error error) {
  this->error_char_->set_value(ByteBuffer::wrap(static_cast<uint8_t>(error)));
  this->error_char_->notify();
}

void ThreadProvisioning::dump_config() {
  ESP_LOGCONFIG(TAG,
                "Thread provisioning (BLE):\n"
                "  Attach timeout: %" PRIu32 " s",
                this->attach_timeout_ / 1000);
#ifdef USE_BINARY_SENSOR
  LOG_BINARY_SENSOR("  ", "Authorizer", this->authorizer_);
#endif
}

}  // namespace esphome::thread_provisioning

#endif
