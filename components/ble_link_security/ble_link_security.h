#pragma once

#include "esphome/core/automation.h"
#include "esphome/core/component.h"
#include "esphome/core/defines.h"

#ifdef USE_ESP32

#include "esphome/components/esp32_ble_server/ble_characteristic.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace esphome::ble_link_security {

class BLELinkSecurity final : public Component {
 public:
  BLELinkSecurity();
  void loop() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_BLUETOOTH; }

  void add_characteristic(const std::string &service, const std::string &characteristic) {
    this->pending_.emplace_back(service, characteristic);
  }
  void set_passkey(uint32_t passkey) { this->passkey_ = passkey; }

  /// Makes a write to `characteristic` need an encrypted link (authenticated with a passkey set); call it before its
  /// service starts, as the permissions are fixed once the stack has the attribute.
  void protect(esp32_ble_server::BLECharacteristic *characteristic);
  /// Forgets every bonded peer, e.g. once the node is provisioned.
  void clear_bonds();

 protected:
  void apply_security_params_();

  std::vector<std::pair<std::string, std::string>> pending_;  // service, characteristic
  std::optional<uint32_t> passkey_;
  bool active_{false};
  uint8_t protected_{0};
};

extern BLELinkSecurity *global_ble_link_security;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

template<typename... Ts> class ClearBondsAction : public Action<Ts...>, public Parented<BLELinkSecurity> {
 public:
  explicit ClearBondsAction(BLELinkSecurity *parent) { this->set_parent(parent); }
  void play(const Ts &...x) override { this->parent_->clear_bonds(); }
};

}  // namespace esphome::ble_link_security

#endif
