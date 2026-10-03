#!/usr/bin/env bash
# Explicit live-node validation. This script is never part of the default test suite.
set -euo pipefail
: "${INCUS_TEST_POOL:?Set INCUS_TEST_POOL to a disposable existing btrfs/ZFS pool}"
: "${INCUS_TEST_LISTEN_IP:?Set INCUS_TEST_LISTEN_IP to a concrete address on the disposable node}"
incus info >/dev/null
cargo test -p wings-rs live_incus_lifecycle_volume_console_and_forwards -- --ignored --nocapture
