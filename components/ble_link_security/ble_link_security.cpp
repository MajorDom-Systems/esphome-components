#include "ble_link_security.h"

#ifdef USE_ESP32

#include "esphome/components/esp32_ble/ble.h"
#include "esphome/components/esp32_ble_server/ble_server.h"
#include "esphome/core/log.h"

#include <esp_gap_ble_api.h>

namespace esphome::ble_link_security {

using esp32_ble::ESPBTUUID;
using esp32_ble_server::BLECharacteristic;

static const char *const TAG = "ble_link_security";

BLELinkSecurity *global_ble_link_security = nullptr;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

// BLECharacteristic (final) keeps its attribute permissions protected, with no setter: reached through the explicit
// instantiation rule (access isn't checked on its template arguments). Proposed upstream as set_permissions().
using PermissionsMember = esp_gatt_perm_t BLECharacteristic::*;
PermissionsMember permissions_member();
template<PermissionsMember M> struct PermissionsAccess {
  friend PermissionsMember permissions_member() { return M; }
};
template struct PermissionsAccess<&BLECharacteristic::permissions_>;

BLELinkSecurity::BLELinkSecurity() { global_ble_link_security = this; }

void BLELinkSecurity::protect(BLECharacteristic *characteristic) {
  if (characteristic->is_created()) {
    ESP_LOGE(TAG, "A characteristic was created before it could be protected");
    this->mark_failed();
    return;
  }
  esp_gatt_perm_t write = this->passkey_.has_value() ? ESP_GATT_PERM_WRITE_ENC_MITM : ESP_GATT_PERM_WRITE_ENCRYPTED;
  characteristic->*permissions_member() = ESP_GATT_PERM_READ | write;
  this->protected_++;
}

void BLELinkSecurity::loop() {
  // the stack's security parameters are set again by esp32_ble each time it starts: ours follow
  bool active = esp32_ble::global_ble != nullptr && esp32_ble::global_ble->is_active();
  if (active && !this->active_)
    this->apply_security_params_();
  this->active_ = active;

  // services of other components (esp32_improv) appear in their loop; their characteristics reach the stack only
  // after the service's own creation round trip, so they're caught here in time
  if (esp32_ble_server::global_ble_server == nullptr)
    return;
  for (auto it = this->pending_.begin(); it != this->pending_.end();) {
    auto *service = esp32_ble_server::global_ble_server->get_service(ESPBTUUID::from_raw(it->first));
    auto *characteristic = service ? service->get_characteristic(ESPBTUUID::from_raw(it->second)) : nullptr;
    if (characteristic == nullptr) {
      ++it;
      continue;
    }
    this->protect(characteristic);
    it = this->pending_.erase(it);
  }
}

void BLELinkSecurity::apply_security_params_() {
  // refuse a pairing weaker than esp32_ble's auth_req_mode (Secure Connections, and MITM with a passkey), instead of
  // falling back to legacy pairing
  uint8_t only_specified = ESP_BLE_ONLY_ACCEPT_SPECIFIED_AUTH_ENABLE;
  if (esp_ble_gap_set_security_param(ESP_BLE_SM_ONLY_ACCEPT_SPECIFIED_SEC_AUTH, &only_specified, sizeof(uint8_t)) !=
      ESP_OK)
    ESP_LOGE(TAG, "Could not require Secure Connections");
  if (this->passkey_.has_value()) {
    uint32_t passkey = *this->passkey_;
    if (esp_ble_gap_set_security_param(ESP_BLE_SM_SET_STATIC_PASSKEY, &passkey, sizeof(uint32_t)) != ESP_OK)
      ESP_LOGE(TAG, "Could not set the passkey");
  }
}

void BLELinkSecurity::clear_bonds() {
  int count = esp_ble_get_bond_device_num();
  if (count <= 0)
    return;
  std::vector<esp_ble_bond_dev_t> bonds(count);
  esp_ble_get_bond_device_list(&count, bonds.data());
  for (int i = 0; i < count; i++)
    esp_ble_remove_bond_device(bonds[i].bd_addr);
  ESP_LOGI(TAG, "Cleared %d bond(s)", count);
}

void BLELinkSecurity::dump_config() {
  ESP_LOGCONFIG(TAG,
                "BLE link security:\n"
                "  Pairing: LE Secure Connections, %s\n"
                "  Protected characteristics: %u (%u pending)",
                this->passkey_.has_value() ? "passkey" : "Just Works (no MITM protection)", this->protected_,
                static_cast<unsigned>(this->pending_.size()));
}

}  // namespace esphome::ble_link_security

#endif
