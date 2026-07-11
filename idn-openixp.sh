#!/usr/bin/env bash
set -uo pipefail

# Cron-safe baseline environment.
# Cron biasanya memberi environment minimal; PATH eksplisit membuat command
# seperti named-checkconf/rndc/systemctl tetap mudah ditemukan di root crontab.
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin${PATH:+:${PATH}}"
export LC_ALL="${LC_ALL:-C}"
umask 022

SCRIPT_VERSION="1.0"
RUN_ID="$(date '+%Y%m%d-%H%M%S')"
START_EPOCH="$(date '+%s')"

# =====================================================================
# BIND9 COUNTRY ACL GENERATOR v1.0
# First Release : 2026-06-16
# =====================================================================
# DOCNOTE:
#   Script ini membuat file include BIND9 berisi ACL berbasis IP/CIDR.
#   Output default:
#
#       /etc/bind/acl-whitelist.conf
#
#   Format output:
#
#       acl trusted_networks {
#           10.0.0.0/8;
#           172.16.0.0/12;
#           192.168.0.0/16;
#           127.0.0.0/8;
#           ::1/128;
#           ...
#       };
#
#   Source data aktif pada first release:
#     - RFC1918 private IPv4
#     - IPv4 loopback 127.0.0.0/8
#     - IPv6 loopback ::1/128
#     - Google public IP ranges JSON
#     - MikroTik NICE IIX Indonesia
#     - ipverse country aggregated IPv4/IPv6
#     - ebrasha country CIDR IPv4/IPv6
#     - ipdeny country IPv4/IPv6
#     - APNIC delegated latest
#
#   Catatan desain:
#     - Script ini hanya membuat file ACL, bukan otomatis mengedit named.conf.
#     - ACL ini cocok untuk allow-recursion / allow-query-cache pada recursive
#       resolver internal atau resolver terbatas.
#     - Untuk authoritative public DNS, jangan asal membatasi allow-query dengan
#       ACL ini karena authoritative DNS publik biasanya harus dapat di-query
#       oleh publik.
#     - Jangan pakai ACL negara/provider besar untuk allow-transfer kecuali
#       benar-benar paham risikonya. Zone transfer sebaiknya dibatasi ke IP
#       secondary DNS yang spesifik.
#
# CARA INSTALL:
#   install -m 0755 rules-countries_bind9_acl.sh /usr/local/sbin/rules-countries_bind9_acl.sh
#
# CARA PAKAI MANUAL:
#   sudo /usr/local/sbin/rules-countries_bind9_acl.sh
#
# CARA INCLUDE DI BIND9:
#   Tambahkan satu baris ini di /etc/bind/named.conf atau file include utama
#   sebelum ACL dipakai:
#
#       include "/etc/bind/acl-whitelist.conf";
#
#   Contoh pemakaian untuk resolver/cache:
#
#       options {
#           recursion yes;
#           allow-recursion   { trusted_networks; };
#           allow-query-cache { trusted_networks; };
#       };
#
# CARA CEK VALID:
#   named-checkconf /etc/bind/named.conf
#   named-checkconf -p /etc/bind/named.conf >/tmp/named.conf.rendered
#   grep -n 'acl trusted_networks' /tmp/named.conf.rendered
#
# CARA CEK BIND BERJALAN:
#   rndc status
#   systemctl status bind9 --no-pager
#   journalctl -u bind9 -n 80 --no-pager
#
# CARA CEK ACL BEKERJA:
#   Dari IP yang masuk ACL:
#       dig @127.0.0.1 google.com A +short
#
#   Dari client/IP yang tidak masuk ACL, query recursion/cache seharusnya
#   ditolak jika allow-recursion/allow-query-cache memakai ACL ini:
#       dig @IP_SERVER google.com A +short
#
#   Untuk cek dari server langsung apakah named menerima konfigurasi baru:
#       rndc reconfig
#       rndc status
#
# CRONTAB SAFE EXAMPLE:
#   SHELL=/bin/bash
#   PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
#   MAILTO=""
#   15 3 * * * LOG_TO_CONSOLE=0 LOG_FILE_PATH=/var/log/rules-countries_bind9_acl.log /usr/local/sbin/rules-countries_bind9_acl.sh
#
# OPTIONAL ENV:
#   BIND_ACL_CONF="/etc/bind/acl-whitelist.conf" sudo -E bash rules-countries_bind9_acl.sh
#   BIND_MAIN_CONF="/etc/bind/named.conf" sudo -E bash rules-countries_bind9_acl.sh
#   ACL_NAME="trusted_networks" sudo -E bash rules-countries_bind9_acl.sh
#   BIND_SERVICE="bind9" sudo -E bash rules-countries_bind9_acl.sh
#   COUNTRIES_CSV="sg,my,th,ph,vn,kh,la,mm,bn,tl,au,hk" sudo -E bash rules-countries_bind9_acl.sh
#   RELOAD_BIND=0 sudo -E bash rules-countries_bind9_acl.sh
#   RELOAD_FATAL=1 sudo -E bash rules-countries_bind9_acl.sh
#   LOG_TO_CONSOLE=0 sudo -E bash rules-countries_bind9_acl.sh
#   LOG_FILE_PATH="/var/log/rules-countries_bind9_acl.log" sudo -E bash rules-countries_bind9_acl.sh
#   MAX_PARALLEL=8 sudo -E bash rules-countries_bind9_acl.sh
#
# CHANGELOG v1.0:
#   - First release.
#   - Generate BIND9 ACL include file from country/provider CIDR sources.
#   - Output uses native BIND9 ACL syntax, not Nginx allow/deny syntax.
#   - Validate generated ACL with named-checkconf wrapper before deploy.
#   - Validate main BIND configuration after deploy when BIND_MAIN_CONF exists.
#   - Reload BIND with rndc reconfig, fallback to systemctl/service reload.
#   - Safe deploy: temporary file, backup, validation, and keep output file
#     when reload/reconfig fails so the generated result is never lost.
#   - Cron-safe console/log format: plain ASCII, no emoji, no color.
#   - ShellCheck-friendly Bash style: safe quoting, initialized variables,
#     nounset-safe assignments, and controlled background jobs.
# =====================================================================

BIND_ACL_CONF="${BIND_ACL_CONF:-/etc/bind/acl-network.conf}"
BIND_MAIN_CONF="${BIND_MAIN_CONF:-/etc/bind/named.conf}"
ACL_NAME="${ACL_NAME:-acl_dns}"
BACKUP_CONF="${BACKUP_CONF:-${BIND_ACL_CONF}.bak}"
BIND_SERVICE="${BIND_SERVICE:-named}"
RELOAD_BIND="${RELOAD_BIND:-1}"
RELOAD_FATAL="${RELOAD_FATAL:-0}"
#COUNTRIES_CSV="${COUNTRIES_CSV:-sg,my,th,ph,vn,kh,la,mm,bn,tl,au,hk}"
COUNTRIES_CSV="${COUNTRIES_CSV:-sg,tl,id}"
DEBUG_TAIL="${DEBUG_TAIL:-0}"
LOG_TO_CONSOLE="${LOG_TO_CONSOLE:-1}"
LOG_FILE_PATH="${LOG_FILE_PATH:-/var/log/rules-countries_bind9_acl.log}"
MAX_PARALLEL="${MAX_PARALLEL:-8}"
RETRIES="${RETRIES:-3}"
TIMEOUT="${TIMEOUT:-20}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-10}"
RETRY_SLEEP="${RETRY_SLEEP:-2}"

IPVERSE_URL="https://raw.githubusercontent.com/ipverse/rir-ip/master/country"
EBRASHA_URL="https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR"
IPDENY_V4="https://www.ipdeny.com/ipblocks/data/countries"
IPDENY_V6="https://www.ipdeny.com/ipv6/ipaddresses/blocks"
NICE_URL="https://ixp.mikrotik.co.id/download/nice.rsc"
NICE_FALLBACK_URL="http://ixp.mikrotik.co.id/download/nice.rsc"
GOOGLE_JSON="https://www.gstatic.com/ipranges/goog.json"
APNIC_URL="https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest"

TMP_DIR=""
TMP_RAW=""
TMP_IPS=""
TMP_INVALID=""
TMP_APNIC=""
LOG_FILE=""
BIND_DIR=""
BIND_BASE=""
declare -a COUNTRIES=()

RE_V4='^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'
RE_HAS_COLON=':'

cleanup() {
    if [[ -n "${TMP_DIR}" && "${TMP_DIR}" == /tmp/bind9_acl.* && -d "${TMP_DIR}" ]]; then
        rm -rf -- "${TMP_DIR}"
    fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

console_write() {
    if [[ "${LOG_TO_CONSOLE}" == "1" ]]; then
        printf '%s\n' "$1" >&2
    fi
}

log_line() {
    local level=$1
    local message=$2
    local now
    local line

    now="$(date '+%Y-%m-%d %H:%M:%S')"
    line="$(printf '%s | %-5s | %s' "${now}" "${level}" "${message}")"
    console_write "${line}"
    [[ -n "${LOG_FILE}" ]] && printf '%s\n' "${line}" >> "${LOG_FILE}"
}

log_info() { log_line "INFO" "$1"; }
log_ok()   { log_line "OK" "$1"; }
log_warn() { log_line "WARN" "$1"; }
log_fail() { log_line "FAIL" "$1"; }

print_rule() {
    console_write '-------------------------------------------------------------------------------'
    [[ -n "${LOG_FILE}" ]] && printf '%s\n' '-------------------------------------------------------------------------------' >> "${LOG_FILE}"
}

print_kv() {
    local key=$1
    local value=$2
    local line

    line="$(printf '  %-18s : %s' "${key}" "${value}")"
    console_write "${line}"
    [[ -n "${LOG_FILE}" ]] && printf '%s\n' "${line}" >> "${LOG_FILE}"
}

print_file_indented() {
    local file_path=$1
    local line

    [[ -s "${file_path}" ]] || return 0
    while IFS= read -r line; do
        console_write "       ${line}"
        [[ -n "${LOG_FILE}" ]] && printf '       %s\n' "${line}" >> "${LOG_FILE}"
    done < "${file_path}"
}

fail_exit() {
    log_fail "$1"
    exit 1
}

show_help() {
    cat <<EOF
BIND9 Country ACL Generator v${SCRIPT_VERSION}

Usage:
  sudo $0 [--help] [--version]

Default output:
  ${BIND_ACL_CONF}

Important steps after first install:
  1. Run the generator:
       sudo $0

  2. Include the generated ACL file in BIND9 config before using the ACL:
       include "${BIND_ACL_CONF}";

  3. Use the ACL in named.conf.options, for example:
       allow-recursion   { ${ACL_NAME}; };
       allow-query-cache { ${ACL_NAME}; };

Validation commands:
  named-checkconf ${BIND_MAIN_CONF}
  named-checkconf -p ${BIND_MAIN_CONF} >/tmp/named.conf.rendered
  grep -n 'acl ${ACL_NAME}' /tmp/named.conf.rendered

Runtime check:
  rndc status
  rndc reconfig
  systemctl status ${BIND_SERVICE} --no-pager
  journalctl -u ${BIND_SERVICE} -n 80 --no-pager
EOF
}

parse_args() {
    while (($# > 0)); do
        case "$1" in
            -h|--help)
                show_help
                exit 0
                ;;
            --version)
                printf '%s\n' "${SCRIPT_VERSION}"
                exit 0
                ;;
            *)
                printf 'Unknown argument: %s\n' "$1" >&2
                printf 'Use --help for usage.\n' >&2
                exit 2
                ;;
        esac
        shift
    done
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "Error: run as root." >&2
        exit 1
    fi
}

check_acl_name() {
    if [[ ! "${ACL_NAME}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        echo "Error: ACL_NAME harus valid untuk BIND identifier, contoh: trusted_networks" >&2
        echo "       Gunakan huruf, angka, underscore, dan tidak boleh diawali angka." >&2
        exit 1
    fi
}

check_required_commands() {
    local cmd
    local missing=0

    for cmd in awk sed grep sort wc mktemp dirname basename cp mv chmod tail cat tr mkdir named-checkconf; do
        if ! command -v "${cmd}" >/dev/null 2>&1; then
            echo "Missing required command: ${cmd}" >&2
            missing=1
        fi
    done

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        echo "Missing required downloader: curl or wget" >&2
        missing=1
    fi

    if [[ "${missing}" -ne 0 ]]; then
        exit 1
    fi
}

init_paths() {
    local log_dir

    BIND_DIR="$(dirname -- "${BIND_ACL_CONF}")"
    BIND_BASE="$(basename -- "${BIND_ACL_CONF}")"

    if [[ ! -d "${BIND_DIR}" ]]; then
        fail_exit "Directory BIND tidak ditemukan: ${BIND_DIR}"
    fi

    TMP_DIR="$(mktemp -d /tmp/bind9_acl.XXXXXX)" || fail_exit "Gagal membuat temporary directory"
    TMP_RAW="${TMP_DIR}/raw.txt"
    TMP_IPS="${TMP_DIR}/ips.txt"
    TMP_INVALID="${TMP_DIR}/invalid.txt"
    TMP_APNIC="${TMP_DIR}/apnic.txt"
    LOG_FILE="${LOG_FILE_PATH}"

    log_dir="$(dirname -- "${LOG_FILE}")"
    mkdir -p -- "${log_dir}" || fail_exit "Gagal membuat directory log: ${log_dir}"
    : >> "${LOG_FILE}"
    : > "${TMP_RAW}"
    : > "${TMP_IPS}"
    : > "${TMP_INVALID}"
    : > "${TMP_APNIC}"
}

normalize_countries() {
    local raw
    local item
    local lower
    local exists
    local current
    local -a parts=()

    raw="${COUNTRIES_CSV// /}"
    IFS=',' read -r -a parts <<< "${raw}"

    for item in "${parts[@]}"; do
        [[ -n "${item}" ]] || continue
        lower="${item,,}"

        if [[ ! "${lower}" =~ ^[a-z]{2}$ ]]; then
            log_warn "Country code tidak valid dan dilewati: ${item}"
            continue
        fi

        if [[ "${lower}" == "id" ]]; then
            log_warn "ID dilewati dari COUNTRIES_CSV karena Indonesia diproses khusus"
            continue
        fi

        exists=0
        for current in "${COUNTRIES[@]}"; do
            if [[ "${current}" == "${lower}" ]]; then
                exists=1
                break
            fi
        done
        [[ "${exists}" -eq 1 ]] && continue
        COUNTRIES+=("${lower}")
    done
}

country_list_upper() {
    local cc
    local first=1

    if [[ "${#COUNTRIES[@]}" -eq 0 ]]; then
        printf '%s' '-'
        return 0
    fi

    for cc in "${COUNTRIES[@]}"; do
        if [[ "${first}" -eq 1 ]]; then
            first=0
        else
            printf ', '
        fi
        printf '%s' "${cc^^}"
    done
}

print_header() {
    print_rule
    console_write "BIND9 COUNTRY ACL GENERATOR v${SCRIPT_VERSION}"
    [[ -n "${LOG_FILE}" ]] && printf 'BIND9 COUNTRY ACL GENERATOR v%s\n' "${SCRIPT_VERSION}" >> "${LOG_FILE}"
    print_rule
    print_kv "Run ID" "${RUN_ID}"
    print_kv "Date" "$(date '+%Y-%m-%d %H:%M:%S %Z')"
    print_kv "User" "$(id -un 2>/dev/null || whoami)"
    print_kv "ACL file" "${BIND_ACL_CONF}"
    print_kv "ACL name" "${ACL_NAME}"
    print_kv "Main conf" "${BIND_MAIN_CONF}"
    print_kv "Countries" "ID + $(country_list_upper)"
    print_kv "Max parallel" "${MAX_PARALLEL}"
    print_rule
}

print_summary() {
    local ip_count=$1
    local duration
    local end_epoch

    end_epoch="$(date '+%s')"
    duration=$((end_epoch - START_EPOCH))

    print_rule
    console_write "SUMMARY"
    [[ -n "${LOG_FILE}" ]] && printf 'SUMMARY\n' >> "${LOG_FILE}"
    print_rule
    print_kv "Status" "SUCCESS"
    print_kv "ACL file" "${BIND_ACL_CONF}"
    print_kv "ACL name" "${ACL_NAME}"
    print_kv "Backup" "${BACKUP_CONF}"
    print_kv "Final CIDR" "${ip_count}"
    print_kv "Reload BIND" "${RELOAD_BIND}"
    print_kv "Reload fatal" "${RELOAD_FATAL}"
    print_kv "Duration" "${duration}s"
    print_kv "Build log" "${LOG_FILE}"
    print_rule
}

http_get() {
    local url=$1

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL \
            --connect-timeout "${CONNECT_TIMEOUT}" \
            --max-time "${TIMEOUT}" \
            --retry 0 \
            --user-agent "bind9-acl-generator/${SCRIPT_VERSION}" \
            "${url}"
    else
        wget -qO- \
            --timeout="${TIMEOUT}" \
            --tries=1 \
            --user-agent="bind9-acl-generator/${SCRIPT_VERSION}" \
            "${url}"
    fi
}

fetch_plain() {
    local url=$1
    local label=$2
    local tries=0
    local out

    while ((tries < RETRIES)); do
        out="$(http_get "${url}" 2>/dev/null | sed 's/\r$//' | grep -E '^[0-9A-Fa-f:./]+$')" || true
        if [[ -n "${out}" ]]; then
            printf '%s\n' "${out}"
            return 0
        fi
        ((tries++))
        ((tries < RETRIES)) && sleep "${RETRY_SLEEP}"
    done

    log_warn "Gagal mengambil ${label} setelah ${RETRIES} percobaan"
    return 1
}

fetch_awk() {
    local url=$1
    local awk_prog=$2
    local label=${3:-Unknown source}
    local tries=0
    local out

    while ((tries < RETRIES)); do
        out="$(http_get "${url}" 2>/dev/null | awk "${awk_prog}")" || true
        if [[ -n "${out}" ]]; then
            printf '%s\n' "${out}"
            return 0
        fi
        ((tries++))
        ((tries < RETRIES)) && sleep "${RETRY_SLEEP}"
    done

    log_warn "Gagal mengambil ${label} setelah ${RETRIES} percobaan"
    return 1
}

fetch_nice() {
    local tries=0
    local url
    local out

    while ((tries < RETRIES)); do
        for url in "${NICE_URL}" "${NICE_FALLBACK_URL}"; do
            out="$(http_get "${url}" 2>/dev/null | sed -n '
                s|.*address="\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}/[0-9]\{1,2\}\)".*|\1|p
                s|.*address="\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)".*|\1|p
            ')" || true
            if [[ -n "${out}" ]]; then
                printf '%s\n' "${out}"
                return 0
            fi
        done
        ((tries++))
        ((tries < RETRIES)) && sleep "${RETRY_SLEEP}"
    done

    log_warn "Gagal mengambil nice.rsc setelah ${RETRIES} percobaan"
    return 1
}

fetch_google() {
    local tries=0
    local out

    while ((tries < RETRIES)); do
        out="$(http_get "${GOOGLE_JSON}" 2>/dev/null \
            | grep -o '"ipv[46]Prefix"[[:space:]]*:[[:space:]]*"[0-9A-Fa-f.:/]*"' \
            | sed 's/.*"\([0-9A-Fa-f.:/]*\)".*/\1/')" || true
        if [[ -n "${out}" ]]; then
            printf '%s\n' "${out}"
            return 0
        fi
        ((tries++))
        ((tries < RETRIES)) && sleep "${RETRY_SLEEP}"
    done

    log_warn "Gagal mengambil Google IP ranges setelah ${RETRIES} percobaan"
    return 1
}

fetch_apnic_once() {
    local tries=0

    while ((tries < RETRIES)); do
        if http_get "${APNIC_URL}" > "${TMP_APNIC}" 2>/dev/null && [[ -s "${TMP_APNIC}" ]]; then
            log_ok "APNIC delegated latest"
            return 0
        fi
        ((tries++))
        ((tries < RETRIES)) && sleep "${RETRY_SLEEP}"
    done

    log_warn "Gagal mengambil APNIC setelah ${RETRIES} percobaan"
    return 1
}

parse_apnic_python() {
    local output_file=$1
    shift

    python3 - "${TMP_APNIC}" "${output_file}" "$@" <<'PY'
import ipaddress
import sys

src = sys.argv[1]
dst = sys.argv[2]
wanted = {cc.upper() for cc in sys.argv[3:]}
items = []

with open(src, 'r', encoding='utf-8', errors='replace') as fh:
    for raw in fh:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) < 7:
            continue
        _, cc, kind, start, value, *_rest = parts
        cc = cc.upper()
        if cc not in wanted:
            continue
        if kind == 'ipv4':
            try:
                count = int(value)
                first = ipaddress.IPv4Address(start)
                last = ipaddress.IPv4Address(int(first) + count - 1)
                for net in ipaddress.summarize_address_range(first, last):
                    items.append(net.with_prefixlen)
            except Exception:
                continue
        elif kind == 'ipv6':
            try:
                prefix = int(value)
                items.append(ipaddress.IPv6Network(f'{start}/{prefix}', strict=False).with_prefixlen)
            except Exception:
                continue

with open(dst, 'w', encoding='utf-8') as out:
    for item in sorted(set(items)):
        out.write(item + '\n')
PY
}

parse_apnic_awk() {
    local output_file=$1
    shift
    local cc
    local upper

    : > "${output_file}"
    for cc in "$@"; do
        upper="${cc^^}"
        awk -F'|' -v cc="${upper}" '
            $2 == cc && $3 == "ipv4" && $5 + 0 > 0 {
                n = int($5)
                bits = 0
                while (2 ^ bits < n) bits++
                if (2 ^ bits == n) print $4 "/" (32 - bits)
            }
            $2 == cc && $3 == "ipv6" && $5 + 0 >= 0 && $5 + 0 <= 128 {
                print $4 "/" $5
            }
        ' "${TMP_APNIC}" >> "${output_file}"
    done
}

parse_apnic() {
    local output_file="${TMP_DIR}/apnic-parsed.txt"
    local -a wanted=(id)
    local cc

    for cc in "${COUNTRIES[@]}"; do
        wanted+=("${cc}")
    done

    if [[ ! -s "${TMP_APNIC}" ]]; then
        return 1
    fi

    if command -v python3 >/dev/null 2>&1; then
        parse_apnic_python "${output_file}" "${wanted[@]}" || return 1
    else
        parse_apnic_awk "${output_file}" "${wanted[@]}" || return 1
    fi

    if [[ -s "${output_file}" ]]; then
        cat "${output_file}" >> "${TMP_RAW}"
        return 0
    fi

    return 1
}

fetch_country_sources() {
    local cc=$1
    local out_file=$2
    local upper

    upper="${cc^^}"
    : > "${out_file}"

    fetch_plain "${IPVERSE_URL}/${cc}/ipv4-aggregated.txt" "IPv4 ${upper} (ipverse)" >> "${out_file}" || true
    fetch_plain "${EBRASHA_URL}/${upper}-ipv4-Hackers.Zone.txt" "IPv4 ${upper} (ebrasha)" >> "${out_file}" || true
    fetch_awk "${IPDENY_V4}/${cc}.zone" '{print $1}' "IPv4 ${upper} (ipdeny)" >> "${out_file}" || true
    fetch_plain "${IPVERSE_URL}/${cc}/ipv6-aggregated.txt" "IPv6 ${upper} (ipverse)" >> "${out_file}" || true
    fetch_plain "${EBRASHA_URL}/${upper}-ipv6-Hackers.Zone.txt" "IPv6 ${upper} (ebrasha)" >> "${out_file}" || true
    fetch_awk "${IPDENY_V6}/${cc}.zone" '{print $1}' "IPv6 ${upper} (ipdeny)" >> "${out_file}" || true
}

wait_for_job_slot() {
    local current_jobs

    while true; do
        current_jobs="$(jobs -pr | wc -l | tr -d ' ')"
        if [[ "${current_jobs}" -lt "${MAX_PARALLEL}" ]]; then
            break
        fi
        sleep 0.2
    done
}

fetch_all_country_sources_parallel() {
    local cc
    local out_file
    local fail=0
    local -a files=()
    local -a pids=()

    for cc in "${COUNTRIES[@]}"; do
        wait_for_job_slot
        out_file="${TMP_DIR}/country-${cc}.txt"
        files+=("${out_file}")
        fetch_country_sources "${cc}" "${out_file}" &
        pids+=("$!")
    done

    for cc in "${pids[@]}"; do
        wait "${cc}" || fail=1
    done

    for out_file in "${files[@]}"; do
        [[ -s "${out_file}" ]] && cat "${out_file}" >> "${TMP_RAW}"
    done

    [[ "${fail}" -eq 0 ]]
}

normalize_and_aggregate_python() {
    python3 - "${TMP_RAW}" "${TMP_IPS}" "${TMP_INVALID}" <<'PY'
import ipaddress
import re
import sys

src, dst, bad = sys.argv[1], sys.argv[2], sys.argv[3]
networks_v4 = []
networks_v6 = []
invalid = []

with open(src, 'r', encoding='utf-8', errors='replace') as fh:
    for raw in fh:
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        line = re.sub(r'\s+#.*$', '', line).strip().rstrip(';').strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            invalid.append(line)
            continue
        if net.version == 4:
            networks_v4.append(net)
        else:
            networks_v6.append(net)

collapsed_v4 = list(ipaddress.collapse_addresses(networks_v4))
collapsed_v6 = list(ipaddress.collapse_addresses(networks_v6))
collapsed_v4.sort(key=lambda n: (int(n.network_address), n.prefixlen))
collapsed_v6.sort(key=lambda n: (int(n.network_address), n.prefixlen))

with open(dst, 'w', encoding='utf-8') as out:
    for net in collapsed_v4 + collapsed_v6:
        out.write(net.with_prefixlen + '\n')

with open(bad, 'w', encoding='utf-8') as err:
    for item in invalid:
        err.write(item + '\n')
PY
}

normalize_and_aggregate_fallback() {
    local tmp4
    local tmp6

    tmp4="$(mktemp "${TMP_DIR}/ipv4.XXXXXX")" || return 1
    tmp6="$(mktemp "${TMP_DIR}/ipv6.XXXXXX")" || return 1

    grep -E "${RE_V4}" "${TMP_RAW}" | sort -u > "${tmp4}" || true
    grep -E "${RE_HAS_COLON}" "${TMP_RAW}" | sort -u > "${tmp6}" || true

    if command -v aggregate >/dev/null 2>&1 && [[ -s "${tmp4}" ]]; then
        aggregate -q < "${tmp4}" > "${tmp4}.agg" 2>/dev/null && mv -f -- "${tmp4}.agg" "${tmp4}" || rm -f -- "${tmp4}.agg"
    fi

    if command -v aggregate6 >/dev/null 2>&1 && [[ -s "${tmp6}" ]]; then
        aggregate6 < "${tmp6}" > "${tmp6}.agg" 2>/dev/null && mv -f -- "${tmp6}.agg" "${tmp6}" || rm -f -- "${tmp6}.agg"
    fi

    cat "${tmp4}" "${tmp6}" | sort -u > "${TMP_IPS}"
    : > "${TMP_INVALID}"
}

normalize_and_aggregate() {
    if command -v python3 >/dev/null 2>&1; then
        normalize_and_aggregate_python
    else
        normalize_and_aggregate_fallback
    fi
}

count_lines() {
    awk 'END { print NR + 0 }' "$1"
}

build_bind_acl_conf() {
    local output_file=$1
    local ip_count=$2
    local ipv4_count
    local ipv6_count
    local line

    ipv4_count="$(grep -Ec "${RE_V4}" "${TMP_IPS}" || true)"
    ipv6_count="$(grep -Ec "${RE_HAS_COLON}" "${TMP_IPS}" || true)"

    {
        printf '/* ======================================================= */\n'
        printf '/* BIND9 Country ACL Whitelist -- Generated %s */\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf '/* Script             : bind9-acl-generator v%s */\n' "${SCRIPT_VERSION}"
        printf '/* ACL name           : %s */\n' "${ACL_NAME}"
        printf '/* Countries          : ID + %s */\n' "$(country_list_upper)"
        printf '/* Final unique CIDR  : %s */\n' "${ip_count}"
        printf '/* IPv4 CIDR          : %s */\n' "${ipv4_count}"
        printf '/* IPv6 CIDR          : %s */\n' "${ipv6_count}"
        printf '/* ======================================================= */\n\n'
        printf 'acl %s {\n' "${ACL_NAME}"

        printf '    // --- IPv4 ------------------------------------------\n'
        while IFS= read -r line; do
            [[ -n "${line}" ]] && printf '    %s;\n' "${line}"
        done < <(grep -E "${RE_V4}" "${TMP_IPS}" | sort -u)

        printf '\n    // --- IPv6 ------------------------------------------\n'
        while IFS= read -r line; do
            [[ -n "${line}" ]] && printf '    %s;\n' "${line}"
        done < <(grep -E "${RE_HAS_COLON}" "${TMP_IPS}" | sort -u)

        printf '};\n'
    } > "${output_file}"

    sed 's/[[:space:]]*$//' "${output_file}" > "${output_file}.tmp"
    mv -f -- "${output_file}.tmp" "${output_file}"
}

validate_bind_acl_file() {
    local candidate_file=$1
    local wrapper_conf
    local test_log

    wrapper_conf="${TMP_DIR}/named-wrapper.conf"
    test_log="${TMP_DIR}/named-checkconf-acl.log"

    printf 'include "%s";\n' "${candidate_file}" > "${wrapper_conf}"

    log_info "Memvalidasi syntax ACL dengan named-checkconf ..."
    if ! named-checkconf "${wrapper_conf}" > "${test_log}" 2>&1; then
        log_fail "ACL BIND9 invalid"
        print_file_indented "${test_log}"
        return 1
    fi

    print_file_indented "${test_log}"
    log_ok "ACL BIND9 syntax valid"
    return 0
}

validate_bind_main_conf() {
    local test_log

    if [[ ! -f "${BIND_MAIN_CONF}" ]]; then
        log_warn "Main conf tidak ditemukan, skip full named-checkconf: ${BIND_MAIN_CONF}"
        return 0
    fi

    test_log="${TMP_DIR}/named-checkconf-main.log"
    log_info "Memvalidasi konfigurasi utama BIND: ${BIND_MAIN_CONF}"
    if ! named-checkconf "${BIND_MAIN_CONF}" > "${test_log}" 2>&1; then
        log_fail "Konfigurasi utama BIND invalid"
        print_file_indented "${test_log}"
        return 1
    fi

    print_file_indented "${test_log}"
    log_ok "Konfigurasi utama BIND valid"
    return 0
}

reload_bind() {
    local svc
    local -a services=()

    if [[ "${RELOAD_BIND}" != "1" ]]; then
        log_warn "Reload BIND dilewati karena RELOAD_BIND=${RELOAD_BIND}"
        return 0
    fi

    if command -v rndc >/dev/null 2>&1; then
        if rndc reconfig >/dev/null 2>&1; then
            log_ok "BIND reconfig via rndc berhasil"
            return 0
        fi
        log_warn "rndc reconfig gagal, mencoba service reload"
    fi

    services+=("${BIND_SERVICE}")
    [[ "${BIND_SERVICE}" != "bind9" ]] && services+=("bind9")
    [[ "${BIND_SERVICE}" != "named" ]] && services+=("named")

    if command -v systemctl >/dev/null 2>&1; then
        for svc in "${services[@]}"; do
            if systemctl reload "${svc}" >/dev/null 2>&1; then
                log_ok "BIND reload via systemctl berhasil: ${svc}"
                return 0
            fi
        done
    fi

    if command -v service >/dev/null 2>&1; then
        for svc in "${services[@]}"; do
            if service "${svc}" reload >/dev/null 2>&1; then
                log_ok "BIND reload via service berhasil: ${svc}"
                return 0
            fi
        done
    fi

    return 1
}

deploy_and_reload() {
    local generated_file=$1
    local deploy_tmp
    local had_backup=0

    if [[ ! -s "${generated_file}" ]]; then
        fail_exit "File hasil kosong"
    fi

    validate_bind_acl_file "${generated_file}" || exit 1

    deploy_tmp="$(mktemp "${BIND_DIR}/.${BIND_BASE}.tmp.XXXXXX")" || fail_exit "Gagal membuat temporary deploy file"
    cp -f -- "${generated_file}" "${deploy_tmp}" || fail_exit "Gagal menyalin file hasil"
    chmod 644 "${deploy_tmp}" || fail_exit "Gagal chmod temporary deploy file"

    if [[ -f "${BIND_ACL_CONF}" ]]; then
        cp -p -- "${BIND_ACL_CONF}" "${BACKUP_CONF}" || fail_exit "Gagal membuat backup: ${BACKUP_CONF}"
        had_backup=1
        log_ok "Backup dibuat: ${BACKUP_CONF}"
    fi

    mv -f -- "${deploy_tmp}" "${BIND_ACL_CONF}" || fail_exit "Gagal deploy ${BIND_ACL_CONF}"
    chmod 644 "${BIND_ACL_CONF}" || fail_exit "Gagal chmod ${BIND_ACL_CONF}"
    log_ok "File ACL berhasil dibuat: ${BIND_ACL_CONF}"

    if [[ "${had_backup}" -eq 0 ]]; then
        log_info "Backup lama tidak ada karena ini deploy pertama"
    fi

    if ! validate_bind_main_conf; then
        log_fail "Konfigurasi utama BIND invalid, tetapi file ACL tetap disimpan: ${BIND_ACL_CONF}"
        exit 1
    fi

    if [[ "${DEBUG_TAIL}" == "1" ]]; then
        print_rule
        console_write "DEBUG: 20 baris terakhir ${BIND_ACL_CONF}"
        [[ -n "${LOG_FILE}" ]] && printf 'DEBUG: 20 baris terakhir %s\n' "${BIND_ACL_CONF}" >> "${LOG_FILE}"
        tail -20 "${BIND_ACL_CONF}" | while IFS= read -r line; do
            console_write "       ${line}"
            [[ -n "${LOG_FILE}" ]] && printf '       %s\n' "${line}" >> "${LOG_FILE}"
        done
        print_rule
    fi

    if reload_bind; then
        log_ok "ACL berhasil di-deploy -> ${BIND_ACL_CONF}"
        return 0
    fi

    log_warn "Reload/reconfig BIND gagal, tetapi file ACL tetap disimpan: ${BIND_ACL_CONF}"
    log_warn "Periksa rndc/systemd secara manual; gunakan RELOAD_BIND=0 untuk hanya generate file"

    if [[ "${RELOAD_FATAL}" == "1" ]]; then
        exit 1
    fi

    return 0
}

# ====================== MAIN ======================
parse_args "$@"
check_root
check_acl_name
check_required_commands
init_paths
normalize_countries
print_header

# RFC private + loopback
{
    echo "10.0.0.0/8"
    echo "172.16.0.0/12"
    echo "192.168.0.0/16"
    echo "127.0.0.0/8"
    echo "::1/128"
} >> "${TMP_RAW}"

log_info "Mengambil IP Google ..."
fetch_google >> "${TMP_RAW}" || true

log_info "Memproses Indonesia (NICE IIX) ..."
if fetch_nice >> "${TMP_RAW}"; then
    log_ok "MikroTik NICE IIX"
else
    log_fail "MikroTik NICE IIX"
fi

id_ok=0
log_info "Mengambil CIDR Indonesia dari ipverse/ebrasha/ipdeny ..."
fetch_plain "${IPVERSE_URL}/id/ipv4-aggregated.txt" "IPv4 ID (ipverse)" >> "${TMP_RAW}" && id_ok=1 || true
fetch_plain "${EBRASHA_URL}/ID-ipv4-Hackers.Zone.txt" "IPv4 ID (ebrasha)" >> "${TMP_RAW}" && id_ok=1 || true
fetch_awk "${IPDENY_V4}/id.zone" '{print $1}' "IPv4 ID (ipdeny)" >> "${TMP_RAW}" && id_ok=1 || true
fetch_plain "${IPVERSE_URL}/id/ipv6-aggregated.txt" "IPv6 ID (ipverse)" >> "${TMP_RAW}" && id_ok=1 || true
fetch_plain "${EBRASHA_URL}/ID-ipv6-Hackers.Zone.txt" "IPv6 ID (ebrasha)" >> "${TMP_RAW}" && id_ok=1 || true
fetch_awk "${IPDENY_V6}/id.zone" '{print $1}' "IPv6 ID (ipdeny)" >> "${TMP_RAW}" && id_ok=1 || true
[[ "${id_ok}" -eq 1 ]] && log_ok "Indonesia CIDR" || log_warn "Indonesia CIDR gagal dari source utama"

log_info "Mengambil blok negara SEA/APAC ..."
if fetch_all_country_sources_parallel; then
    log_ok "SEA/APAC selesai"
else
    log_warn "Sebagian source SEA/APAC gagal, proses tetap lanjut dengan data yang berhasil"
fi

log_info "Mengambil data APNIC ..."
if fetch_apnic_once && parse_apnic; then
    log_ok "APNIC selesai"
else
    log_warn "APNIC gagal atau kosong, proses tetap lanjut"
fi

log_info "Memvalidasi, normalisasi, dan deduplikasi/agregasi CIDR ..."
normalize_and_aggregate || fail_exit "Validasi/deduplikasi CIDR gagal"

invalid_count="$(count_lines "${TMP_INVALID}")"
if [[ "${invalid_count}" -gt 0 ]]; then
    log_warn "CIDR invalid dilewati: ${invalid_count} entri"
fi

IP_COUNT="$(count_lines "${TMP_IPS}")"
log_info "Total entri unik setelah dedup/agregasi: ${IP_COUNT}"

build_bind_acl_conf "${TMP_DIR}/acl-whitelist.conf" "${IP_COUNT}"
deploy_and_reload "${TMP_DIR}/acl-whitelist.conf"

print_summary "${IP_COUNT}"
