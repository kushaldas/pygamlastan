#!/bin/bash
set -euo pipefail

: "${UV_VERSION:=0.11.23}"
: "${RUSTUP_HOME:=/opt/rustup}"
: "${CARGO_HOME:=/opt/cargo}"

export RUSTUP_HOME
export CARGO_HOME
export PATH="${CARGO_HOME}/bin:/opt/python/cp314-cp314/bin:${PATH}"

curl --proto '=https' --tlsv1.2 -sSf \
    -o /tmp/rustup-init \
    https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init
chmod +x /tmp/rustup-init
/tmp/rustup-init -y --profile minimal --default-toolchain stable
rustup update stable
rustup default stable
rustc --version
cargo --version

/opt/python/cp314-cp314/bin/python3.14 -m pip install --upgrade "uv==${UV_VERSION}"
uv --version

/io/build-wheels.sh
