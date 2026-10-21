#pragma once

#include "esphome/core/component.h"
#include "esphome/core/defines.h"

#if defined(USE_ESP32) && defined(USE_OPENTHREAD)

#include "esphome/components/esp32_ble_server/ble_characteristic.h"
#include "esphome/components/esp32_ble_server/ble_server.h"

#ifdef USE_BINARY_SENSOR
#include "esphome/components/binary_sensor/binary_sensor.h"
#endif

#include <openthread/dataset.h>

#include <span>
#include <vector>

namespace esphome::thread_provisioning {

// GATT protocol, modelled on Improv BLE (same frames: command, length, data, checksum = sum of the previous bytes)
static const char *const SERVICE_UUID = "aeb52169-9cc0-4883-8ee7-e3d075fbe600";
static const char *const STATE_UUID = "aeb52169-9cc0-4883-8ee7-e3d075fbe601";   // read, notify: State
static const char *const ERROR_UUID = "aeb52169-9cc0-4883-8ee7-e3d075fbe602";   // read, notify: Error
static const char *const RPC_UUID = "aeb52169-9cc0-4883-8ee7-e3d075fbe603";     // write (chunks): a command frame
static const char *const RESULT_UUID = "aeb52169-9cc0-4883-8ee7-e3d075fbe604";  // read, notify: a result frame

enum State : uint8_t {
  STATE_AWAITING_AUTHORIZATION = 0x01,
  STATE_AUTHORIZED = 0x02,
  STATE_ATTACHING = 0x03,
  STATE_ATTACHED = 0x04,
};

enum Error : uint8_t {
  ERROR_NONE = 0x00,
  ERROR_INVALID_RPC = 0x01,
  ERROR_UNKNOWN_RPC = 0x02,
  ERROR_UNABLE_TO_ATTACH = 0x03,
  ERROR_NOT_AUTHORIZED = 0x04,
  ERROR_INVALID_DATASET = 0x05,
  ERROR_UNKNOWN = 0xFF,
};

enum Command : uint8_t {
  COMMAND_SET_DATASET = 0x01,  // data: the active operational dataset, raw TLVs
};

class ThreadProvisioning final : public Component {
 public:
  void setup() override;
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }

#ifdef USE_BINARY_SENSOR
  void set_authorizer(binary_sensor::BinarySensor *authorizer) { this->authorizer_ = authorizer; }
#endif
  void set_authorized_duration(uint32_t duration) { this->authorized_duration_ = duration; }
  void set_attach_timeout(uint32_t timeout) { this->attach_timeout_ = timeout; }

 protected:
  enum class Phase : uint8_t { CHECKING, STARTING, SERVING, ATTACHING, DONE };

  void check_dataset_();
  void keep_thread_off_();
  void start_service_();
  void serve_();
  void check_attached_();
  void process_incoming_();
  void apply_dataset_(std::span<const uint8_t> data);
  bool authorized_() const;
  void set_state_(State state);
  void set_error_(Error error);

  Phase phase_{Phase::CHECKING};
  State state_{STATE_AUTHORIZED};
  uint32_t authorized_duration_{60000};
  uint32_t authorized_start_{0};
  uint32_t attach_timeout_{60000};
  uint32_t attach_start_{0};
  bool advertising_{false};
  otOperationalDatasetTlvs placeholder_{};  // restored when the node cannot attach with the dataset it was given
  std::vector<uint8_t> incoming_;

  esp32_ble_server::BLEService *service_{nullptr};
  esp32_ble_server::BLECharacteristic *state_char_{nullptr};
  esp32_ble_server::BLECharacteristic *error_char_{nullptr};
  esp32_ble_server::BLECharacteristic *rpc_char_{nullptr};
  esp32_ble_server::BLECharacteristic *result_char_{nullptr};
#ifdef USE_BINARY_SENSOR
  binary_sensor::BinarySensor *authorizer_{nullptr};
#endif
};

}  // namespace esphome::thread_provisioning

#endif
