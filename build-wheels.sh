#!/bin/bash
set -ex

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
export PATH="$HOME/.cargo/bin:$PATH"

curl -LsSf https://astral.sh/uv/install.sh | sh
uv venv --python /opt/python/cp314-cp314/bin/python3.14 /opt/venv
source /opt/venv/bin/activate
uv pip install --upgrade "maturin>=1,<2"
cd /io/
# pygamlastan builds an abi3 (py310+) wheel, so the single artifact produced
# here covers every supported CPython; the cp314 interpreter above is only the
# build driver.
maturin build --release --strip --manylinux --sdist
mkdir -p dist/
cp target/wheels/pygamlastan*.whl ./dist/
cp target/wheels/pygamlastan*.tar.gz ./dist/
