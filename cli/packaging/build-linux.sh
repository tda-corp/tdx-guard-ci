#!/bin/sh
# Builds the Linux executable in AlmaLinux 8 (glibc 2.28), so that it runs on every
# distribution with glibc 2.28 or newer: Debian 10+, Ubuntu 18.10+ (20.04 LTS and later),
# RHEL/Rocky/Alma 8+, Amazon Linux 2023, SLES 15 SP1+. An executable only needs the glibc
# it was linked against or newer, and PyInstaller bundles everything else (libpython,
# OpenSSL, libffi, ...).
#
# AlmaLinux's python3.12 is built with a shared libpython, which PyInstaller requires (the
# manylinux images' Pythons are static and cannot be frozen).
#
# Usage, from the cli/ directory (the directory is mounted at /cli):
#   docker run --rm -v "$PWD":/cli -w /cli \
#     almalinux:8.10@sha256:<digest> sh packaging/build-linux.sh [build.py options]
# The executable lands in cli/dist/ (owned by root on Linux hosts; set BUILD_UID/BUILD_GID
# to hand it back to the calling user).
set -eu

dnf -q -y install python3.12 python3.12-pip binutils >/dev/null
export PYTHONDONTWRITEBYTECODE=1
venv=$(mktemp -d)
python3.12 -m venv "$venv"
"$venv/bin/python" -m pip install -q --disable-pip-version-check --no-cache-dir \
  --require-hashes -r packaging/requirements-build.txt
"$venv/bin/python" packaging/build.py "$@"
ldd --version | head -n 1
if [ -n "${BUILD_UID:-}" ]; then
  chown -R "${BUILD_UID}:${BUILD_GID:-$BUILD_UID}" dist
fi
