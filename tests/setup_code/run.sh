#!/usr/bin/env bash
# Builds components/setup_code against mbedTLS on the host and runs it through the RFC's test vector.
# Usage: tests/setup_code/run.sh <mbedtls source dir>, e.g. ESP-IDF's components/mbedtls/mbedtls (3.6)
set -euo pipefail
mbedtls=$(cd "$1" && pwd)
root=$(cd "$(dirname "$0")/../.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
for source in "$mbedtls"/library/*.c; do
  cc -O1 -I"$mbedtls/include" -I"$mbedtls/library" -c "$source" -o "$build/$(basename "$source" .c).o" &
done
wait
ar rcs "$build/libmbedcrypto.a" "$build"/*.o
c++ -std=c++20 -Wall -Wextra -I"$root/components" -I"$mbedtls/include" -o "$build/test_vector" \
  "$root/tests/setup_code/test_vector.cpp" "$root/components/setup_code/setup_code.cpp" "$build/libmbedcrypto.a"
"$build/test_vector"
