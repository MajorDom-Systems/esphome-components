"""Setup code authentication (Improv via BLE revision 2.5, improv-wifi/website#70): a controller proves it knows the
device's 8-digit code with SPAKE2+, and every command then travels sealed. A library for `esp32_improv` and
`thread_provisioning`, which take a `setup_code:` each.

Give every device its own code, generated at random (e.g. `esphome -s setup_code 1234-5678 compile ...` with
`setup_code: ${setup_code}`) and printed on it. Only a verifier is compiled in (a random salt, the iteration count, w0
and L, as Matter stores it): the code itself is not, and can't be recovered from the firmware but by guessing.
"""

import hashlib
import secrets

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from esphome.components.esp32 import add_idf_sdkconfig_option
import esphome.config_validation as cv

DEPENDENCIES = ["esp32"]

CONF_SETUP_CODE = "setup_code"

ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551  # of the P-256 group
ITERATIONS = 10000  # PBKDF2: the client pays it once per handshake, the device never
FORBIDDEN = {int(str(digit) * 8) for digit in range(10)} | {12345678, 87654321}


def validate_code(value) -> int:
    digits = cv.string_strict(value).replace("-", "").replace(" ", "")
    if len(digits) != 8 or not digits.isdecimal():
        raise cv.Invalid("A setup code is 8 digits, e.g. 1234-5678")
    if int(digits) in FORBIDDEN:
        raise cv.Invalid(f"{value} is too easy to guess: generate the setup code at random")
    return int(digits)


def verifier(code: int, salt: bytes, iterations: int) -> tuple[bytes, bytes]:
    """w0 and L = w1*G from the code, as Matter derives them (the code as a 4-byte little-endian password)."""
    output = hashlib.pbkdf2_hmac("sha256", code.to_bytes(4, "little"), salt, iterations, 80)
    w0, w1 = int.from_bytes(output[:40], "big") % ORDER, int.from_bytes(output[40:], "big") % ORDER
    public = ec.derive_private_key(w1, ec.SECP256R1()).public_key()
    return w0.to_bytes(32, "big"), public.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)


def verifier_args(code: int) -> list:
    """The arguments of `set_setup_code(salt, iterations, w0, L)` for ``code``, with a fresh salt."""
    add_idf_sdkconfig_option("CONFIG_MBEDTLS_HKDF_C", True)
    salt = secrets.token_bytes(16)
    w0, public = verifier(code, salt, ITERATIONS)
    return [list(salt), ITERATIONS, list(w0), list(public)]
