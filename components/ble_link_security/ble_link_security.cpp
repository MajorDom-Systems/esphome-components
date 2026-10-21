#include "ble_link_security.h"

#ifdef USE_ESP32

#include "esphome/components/esp32_ble/ble.h"
#include "esphome/components/esp32_ble_server/ble_server.h"
#include "esphome/core/helpers.h"
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

void BLELinkSecurity::gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param) {
  switch (event) {
    // A central's Pairing Request reaches the GATT server as a security request: unanswered, it times out (ESPHome
    // answers only for its own client links). Whether the pairing is strong enough is the stack's to enforce (auth_req
    // mode, ONLY_ACCEPT_SPECIFIED_SEC_AUTH, key size). For a client link (bluetooth_proxy) this repeats ble_client's
    // own acceptance, which the stack ignores.
    case ESP_GAP_BLE_SEC_REQ_EVT:
      esp_ble_gap_security_rsp(param->ble_security.ble_req.bd_addr, true);
      break;
    case ESP_GAP_BLE_AUTH_CMPL_EVT: {
      const auto &auth = param->ble_security.auth_cmpl;
      char address[MAC_ADDRESS_PRETTY_BUFFER_SIZE];
      format_mac_addr_upper(auth.bd_addr, address);
      if (auth.success) {
        ESP_LOGI(TAG, "[%s] Link encrypted: %s pairing, %s", address,
                 (auth.auth_mode & ESP_LE_AUTH_REQ_SC_ONLY) ? "LE Secure Connections" : "legacy",
                 (auth.auth_mode & ESP_LE_AUTH_REQ_MITM) ? "authenticated (MITM protected)" : "Just Works");
      } else {
        ESP_LOGW(TAG, "[%s] Pairing failed, reason 0x%02X", address, auth.fail_reason);
      }
      break;
    }
    default:
      break;
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
