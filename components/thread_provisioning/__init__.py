"""Runtime Thread dataset provisioning over BLE (Improv-style), for ESPHome nodes that ship without a Thread network.

The node is built with a placeholder network (`openthread: network_key:` only, never `tlv:`): while that placeholder is
its active dataset, the node keeps Thread off and serves a BLE GATT service through which a controller writes the real
active operational dataset (TLVs). It is applied with `otDatasetSetActiveTlvs` (kept in NVS by OpenThread itself), the
node attaches, reports it, and stops advertising. A factory reset brings the placeholder, and the service, back.
"""

import esphome.codegen as cg
from esphome.components import binary_sensor, esp32_ble
from esphome.components.esp32_ble import BTLoggers
import esphome.config_validation as cv
from esphome.const import CONF_ID
import esphome.final_validate as fv

AUTO_LOAD = ["esp32_ble_server", "bytebuffer"]
DEPENDENCIES = ["esp32", "openthread"]

CONF_AUTHORIZER = "authorizer"
CONF_AUTHORIZED_DURATION = "authorized_duration"
CONF_ATTACH_TIMEOUT = "attach_timeout"

thread_provisioning_ns = cg.esphome_ns.namespace("thread_provisioning")
ThreadProvisioning = thread_provisioning_ns.class_("ThreadProvisioning", cg.Component)

CONFIG_SCHEMA = cv.Schema(
    {
        cv.GenerateID(): cv.declare_id(ThreadProvisioning),
        cv.Optional(CONF_AUTHORIZER): cv.Any(cv.none, cv.use_id(binary_sensor.BinarySensor)),
        cv.Optional(CONF_AUTHORIZED_DURATION, default="1min"): cv.positive_time_period_milliseconds,
        cv.Optional(CONF_ATTACH_TIMEOUT, default="60s"): cv.positive_time_period_milliseconds,
    }
).extend(cv.COMPONENT_SCHEMA)


def _final_validate(config):
    openthread = fv.full_config.get().get("openthread", {})
    if "tlv" in openthread or "network_key" not in openthread:
        raise cv.Invalid(
            "thread_provisioning: build with a placeholder network (`openthread: network_key:`, 32 hex digits, the "
            "first one not 0) and no `tlv:`; the node is unprovisioned while the placeholder is its dataset"
        )
    if openthread.get("force_dataset"):
        raise cv.Invalid("thread_provisioning: `force_dataset` would replace the provisioned dataset on every boot")
    return config


FINAL_VALIDATE_SCHEMA = _final_validate


async def to_code(config):
    esp32_ble.register_bt_logger(BTLoggers.GATT, BTLoggers.SMP)
    var = cg.new_Pvariable(config[CONF_ID])
    await cg.register_component(var, config)
    cg.add(var.set_authorized_duration(config[CONF_AUTHORIZED_DURATION]))
    cg.add(var.set_attach_timeout(config[CONF_ATTACH_TIMEOUT]))
    if config.get(CONF_AUTHORIZER) is not None:
        cg.add(var.set_authorizer(await cg.get_variable(config[CONF_AUTHORIZER])))
