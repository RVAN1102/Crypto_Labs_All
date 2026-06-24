#!/usr/bin/env bash
set -euo pipefail

# This helper never replaces the system OpenSSL and never invokes sudo.
# It builds OpenSSL under a user-writable work directory, stages an install,
# and prints the one privileged copy command needed for /opt/openssl-3.5.

OPENSSL_VERSION="${OPENSSL_VERSION:-4.0.1}"
PREFIX="${OPENSSL_PREFIX:-/opt/openssl-4.0}"
WORK_DIR="${OPENSSL_BUILD_DIR:-${HOME}/.cache/lab6-openssl-${OPENSSL_VERSION}}"
SOURCE_ARCHIVE="${WORK_DIR}/openssl-${OPENSSL_VERSION}.tar.gz"
SOURCE_DIR="${WORK_DIR}/openssl-${OPENSSL_VERSION}"
STAGE_DIR="${WORK_DIR}/stage"
DOWNLOAD_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"

case "${PREFIX}" in
    /opt/openssl-4.0|/opt/openssl-4.0/*) ;;
    *)
        echo "ERROR: OPENSSL_PREFIX must remain under /opt/openssl-4.0." >&2
        exit 1
        ;;
esac

for tool in perl make tar; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        echo "ERROR: missing required tool: ${tool}" >&2
        exit 1
    fi
done

if command -v curl >/dev/null 2>&1; then
    downloader=(curl --fail --location --proto '=https' --tlsv1.2 --output)
elif command -v wget >/dev/null 2>&1; then
    downloader=(wget --https-only --output-document)
else
    echo "ERROR: install curl or wget before running this helper." >&2
    exit 1
fi

mkdir -p "${WORK_DIR}"

if [[ ! -f "${SOURCE_ARCHIVE}" ]]; then
    echo "Downloading OpenSSL ${OPENSSL_VERSION} from openssl.org..."
    "${downloader[@]}" "${SOURCE_ARCHIVE}" "${DOWNLOAD_URL}"
fi

if [[ -n "${OPENSSL_SOURCE_SHA256:-}" ]]; then
    echo "${OPENSSL_SOURCE_SHA256}  ${SOURCE_ARCHIVE}" | sha256sum --check -
else
    echo "WARNING: OPENSSL_SOURCE_SHA256 is unset; verify the archive against"
    echo "the digest published by OpenSSL before using this build for grading."
fi

rm -rf "${SOURCE_DIR}" "${STAGE_DIR}"
tar -xzf "${SOURCE_ARCHIVE}" -C "${WORK_DIR}"

cd "${SOURCE_DIR}"
./Configure \
    --prefix="${PREFIX}" \
    --openssldir="${PREFIX}/ssl" \
    shared
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
make test
make install_sw DESTDIR="${STAGE_DIR}"

STAGED_PREFIX="${STAGE_DIR}${PREFIX}"
echo
echo "OpenSSL ${OPENSSL_VERSION} passed its build and test suite."
echo "Staged installation: ${STAGED_PREFIX}"
echo
echo "Review the staged files, then install without replacing system OpenSSL:"
printf '  sudo mkdir -p %q\n' "${PREFIX}"
printf '  sudo cp -a %q/. %q/\n' "${STAGED_PREFIX}" "${PREFIX}"
echo
echo "After that, verify the isolated installation:"
printf '  env LD_LIBRARY_PATH=%q/lib64:%q/lib %q/bin/openssl version -a\n' \
    "${PREFIX}" "${PREFIX}" "${PREFIX}"
printf '  env LD_LIBRARY_PATH=%q/lib64:%q/lib %q/bin/openssl list -signature-algorithms\n' \
    "${PREFIX}" "${PREFIX}" "${PREFIX}"
printf '  env LD_LIBRARY_PATH=%q/lib64:%q/lib %q/bin/openssl list -kem-algorithms\n' \
    "${PREFIX}" "${PREFIX}" "${PREFIX}"
