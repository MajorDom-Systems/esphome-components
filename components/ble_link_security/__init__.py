"""LE Secure Connections for credentials sent to the node over its BLE GATT server (an Improv Wi-Fi password, a Thread
dataset): the characteristics that receive them accept a write only over an encrypted link, so a controller has to pair
before it writes and a secret never crosses the air in clear text.

Pairing is "Just Works": it encrypts the link against passive sniffing but does not authenticate the peer (no MITM
protection). The node answers a central's pairing request itself (ESPHome does so only for its own client links) and the stack refuses anything weaker than
`esp32_ble: auth_req_mode`. With `sc_only` (the examples) nothing is bonded, so no key is stored on either side; with a
bonding mode, bonds are dropped once the node is provisioned (`ble_link_security.clear_bonds`, which
`thread_provisioning` calls itself) and with NVS on a factory reset.
"""

import re

from esphome import automation
import esphome.codegen as cg
from esphome.components import esp32_ble
import esphome.config_validation as cv
from esphome.const import CONF_ID
import esphome.final_validate as fv

AUTO_LOAD = ["esp32_ble_server"]
DEPENDENCIES = ["esp32_ble"]

CONF_CHARACTERISTICS = "characteristics"
CONF_SERVICE = "service"
CONF_CHARACTERISTIC = "characteristic"

ble_link_security_ns = cg.esphome_ns.namespace("ble_link_security")
BLELinkSecurity = ble_link_security_ns.class_("BLELinkSecurity", cg.Component)
ClearBondsAction = ble_link_security_ns.class_("ClearBondsAction", automation.Action)

UUID128_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def uuid128(value):
    value = cv.string_strict(value).lower()
    if not UUID128_PATTERN.match(value):
        raise cv.Invalid(f"{value} is not a 128-bit UUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)")
    return value


CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(BLELinkSecurity),
        cv.GenerateID(esp32_ble.CONF_BLE_ID): cv.use_id(esp32_ble.ESP32BLE),
        # e.g. Improv's RPC command: service 00467768-6228-2272-4663-277478268000, characteristic …8003
        cv.Optional(CONF_CHARACTERISTICS, default=[]): cv.ensure_list(
            cv.Schema({cv.Required(CONF_SERVICE): uuid128, cv.Required(CONF_CHARACTERISTIC): uuid128})
        ),
    }
).extend(cv.COMPONENT_SCHEMA)

SC_MODES = ("sc_only", "sc_bond")  # Just Works: a MITM mode would need a passkey


def _final_validate(config):
    full = fv.full_config.get()
    thread = full.get("thread_provisioning", {}).get("require_encryption", False)
    if not config[CONF_CHARACTERISTICS] and not thread:
        return config  # auto-loaded with nothing to protect
    ble = full.get("esp32_ble", {})
    mode = str(ble.get("auth_req_mode", "")).lower()
    if mode not in SC_MODES:
        raise cv.Invalid(f"ble_link_security: set `esp32_ble: auth_req_mode:` to one of {', '.join(SC_MODES)}")
    if ble.get("min_key_size") != 16:
        raise cv.Invalid("ble_link_security: set `esp32_ble: min_key_size: 16` (no key size downgrade)")
    return config


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    esp32_ble.register_gap_event_handler(await cg.get_variable(config[esp32_ble.CONF_BLE_ID]), var)
    for item in config[CONF_CHARACTERISTICS]:
        cg.add(var.add_characteristic(item[CONF_SERVICE], item[CONF_CHARACTERISTIC]))


@automation.register_action(
    "ble_link_security.clear_bonds",
    ClearBondsAction,
    cv.Schema({cv.GenerateID(): cv.use_id(BLELinkSecurity)}),
)
async def clear_bonds_to_code(config, action_id, template_arg, args):
    parent = await cg.get_variable(config[CONF_ID])
    return cg.new_Pvariable(action_id, template_arg, parent)
