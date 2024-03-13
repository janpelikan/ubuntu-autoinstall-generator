#!/bin/bash
set -Eeuo pipefail

# shellcheck disable=SC2317
function _cleanup() {
        trap - SIGINT SIGTERM ERR EXIT
        if [ -n "${tmpdir+x}" ]; then
                rm -rf "${tmpdir}"
                _log "🧹 Deleted temporary working directory ${tmpdir}"
        fi
}

trap _cleanup SIGINT SIGTERM ERR EXIT

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd -P)
[[ ! -x "$(command -v date)" ]] && echo "💥 date command not found." && exit 1
today=$(date +"%Y-%m-%d")

function _log() {
        echo >&2 -e "[$(date +"%Y-%m-%d %H:%M:%S")] ${1-}"
}

function _die() {
        local msg=$1
        local code=${2-1} # Bash parameter expansion - default exit status 1. See https://wiki.bash-hackers.org/syntax/pe#use_a_default_value
        _log "$msg"
        exit "$code"
}

_usage() {
        cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [-h] [-v] [-a] [-e] [-u user-data-file] [-m meta-data-file] [-k] [-c] [-r] [-s source-iso-file] [-d destination-iso-file]

💁 This script will create fully-automated Ubuntu Focal or Jammy installation media.

Available options:

-h, --help              Print this help and exit
-v, --verbose           Print script debug info
-a, --all-in-one        Bake user-data and meta-data into the generated ISO. By default you will
                        need to boot systems with a CIDATA volume attached containing your
                        autoinstall user-data and meta-data files.
                        For more information see: https://ubuntu.com/server/docs/install/autoinstall-quickstart
-e, --use-hwe-kernel    Force the generated ISO to boot using the hardware enablement (HWE) kernel. Not supported
                        by early Ubuntu 20.04 release ISOs.
-u, --user-data         Path to user-data file. Required if using -a
-m, --meta-data         Path to meta-data file. Will be an empty file if not specified and using -a
-k, --no-verify         Disable GPG verification of the source ISO file. By default SHA256SUMS-${today} and
                        SHA256SUMS-${today}.gpg in ${script_dir} will be used to verify the authenticity and integrity
                        of the source ISO file. If they are not present the latest daily SHA256SUMS will be
                        downloaded and saved in ${script_dir}. The Ubuntu signing key will be downloaded and
                        saved in a new keyring in ${script_dir}
-c, --no-md5            Disable MD5 checksum on boot
-r, --use-release-iso   Use the current release ISO instead of the daily ISO. The file will be used if it already
                        exists.
-s, --source            Source ISO file. By default the latest daily ISO for Ubuntu 20.04 will be downloaded
                        and saved as ${script_dir}/ubuntu-original-${today}.iso
                        That file will be used by default if it already exists.
-d, --destination       Destination ISO file. By default ${script_dir}/ubuntu-autoinstall-${today}.iso will be
                        created, overwriting any existing file.
-i, --image-type        Select major release when using parameters -r, --use-release-iso or not using -s, --source.
-l, --iso-label         Set a label of ISO.
EOF
        exit
}

function _parse_params() {
        # default values of variables set from params
        user_data_file=''
        meta_data_file=''
        download_url="https://cdimage.ubuntu.com/ubuntu-server/jammy/daily-live/current"
        download_iso="jammy-live-server-amd64.iso"
        original_iso="ubuntu-original-${today}.iso"
        source_iso="${script_dir}/${original_iso}"
        iso_label="ubuntu-autoinstall-${today}"
        destination_iso="${script_dir}/ubuntu-autoinstall-${today}.iso"
        sha_suffix="${today}"
        gpg_verify=1
        all_in_one=0
        use_hwe_kernel=0
        md5_checksum=1
        use_release_iso=0
        image_type=''

        while :; do
                case "${1-}" in
                -h | --help) _usage ;;
                -v | --verbose) set -x ;;
                -a | --all-in-one) all_in_one=1 ;;
                -e | --use-hwe-kernel) use_hwe_kernel=1 ;;
                -c | --no-md5) md5_checksum=0 ;;
                -k | --no-verify) gpg_verify=0 ;;
                -r | --use-release-iso) use_release_iso=1 ;;
                -u | --user-data)
                        user_data_file="${2-}"
                        shift
                        ;;
                -s | --source)
                        source_iso="${2-}"
                        shift
                        ;;
                -d | --destination)
                        destination_iso="${2-}"
                        shift
                        ;;
                -m | --meta-data)
                        meta_data_file="${2-}"
                        shift
                        ;;
                -l | --iso-label)
                    case "${2-}" in
                        *[!a-zA-Z0-9-_.]*)
                            _die "Invalid characters in ISO label: ${2-}"
                            ;;
                        *)
                            if [ ${#2} -gt 32 ]; then
                                _die "ISO label ${2-} exceeds 32 characters!"
                            fi
                            iso_label="${2-}"
                            ;;
                    esac
                    shift
                        ;;
                -i | --image-type)
                    case "${2-}" in
                        jammy|focal|22.04|20.04|2204|2004)
                            case "${2-}" in
                                22.04 | 2204) image_type="jammy" ;;
                                20.04 | 2004) image_type="focal" ;;
                                *) image_type="${2-}" ;;
                            esac
                            shift
                            ;;
                        *)
                            _die "Invalid image type: ${2-}. Accepted values are jammy, focal, 22.04, 20.04, 2204, or 2004."
                            ;;
                    esac
                        ;;
                -?*) _die "Unknown option: $1" ;;
                *) break ;;
                esac
                shift
        done

        _log "⏫ Starting up..."

        # check required params and arguments
        if [[ -n "${use_release_iso}" || (-z "${source_iso}" && -z "${use_release_iso}") ]]; then
                [[ -z "${image_type}" ]] && _die "💥 image type not defined. Accepted values are jammy, focal, 22.04, 20.04, 2204, or 2004."
        fi

        if [ ${all_in_one} -ne 0 ]; then
                [[ -z "${user_data_file}" ]] && _die "💥 user-data file was not specified."
                [[ ! -f "$user_data_file" ]] && _die "💥 user-data file could not be found."
                [[ -n "${meta_data_file}" ]] && [[ ! -f "${meta_data_file}" ]] && _die "💥 meta-data file could not be found."
        fi

        if [ "${source_iso}" != "${script_dir}/${original_iso}" ]; then
                [[ ! -f "${source_iso}" ]] && _die "💥 Source ISO file could not be found."
        fi

        if [ "${use_release_iso}" -eq 1 ]; then
                download_url="https://releases.ubuntu.com/${image_type}"
                _log "🔎 Checking for current release..."
                download_iso=$(curl -sSL "${download_url}" | grep -oP 'ubuntu-2[0|2]\.04\.\d*-live-server-amd64\.iso' | head -n 1)
                original_iso="${download_iso}"
                source_iso="${script_dir}/${download_iso}"
                current_release=$(echo "${download_iso}" | cut -f2 -d-)
                sha_suffix="${current_release}"
                _log "💿 Current release is ${current_release}"
        fi

        destination_iso=$(realpath "${destination_iso}")
        source_iso=$(realpath "${source_iso}")

        return 0
}

is_isolinux=false
isolinux_version="bionic,focal"

ubuntu_gpg_key_id="843938DF228D22F7B3742BC0D94AA3F0EFE21092"

_parse_params "$@"

tmpdir=$(mktemp -d)

if [[ ! "${tmpdir}" || ! -d "${tmpdir}" ]]; then
        _die "💥 Could not create temporary working directory."
else
        _log "📁 Created temporary working directory ${tmpdir}"
fi

_log "🔎 Checking for required utilities..."
[[ ! -x "$(command -v xorriso)" ]] && _die "💥 xorriso is not installed. On Ubuntu, install  the 'xorriso' package."
[[ ! -x "$(command -v sed)" ]] && _die "💥 sed is not installed. On Ubuntu, install the 'sed' package."
[[ ! -x "$(command -v curl)" ]] && _die "💥 curl is not installed. On Ubuntu, install the 'curl' package."
[[ ! -x "$(command -v gpg)" ]] && _die "💥 gpg is not installed. On Ubuntu, install the 'gpg' package."
[[ ! -x "$(command -v 7z)" ]] && _die "💥 7z is not installed. On Ubuntu, install the 'p7zip-full' package."
if grep -q -E "${isolinux_version//,/|}" <<< "${image_type}"; then
        # if OS is Alpine release - for containerized usage
        if [[ -f /etc/alpine-release ]]; then
                isohdpfx_path="/usr/share/syslinux/isohdpfx.bin"
        else
        # default - use standard path for Debian/Ubuntu
                isohdpfx_path="/usr/lib/ISOLINUX/isohdpfx.bin"
        fi
        [[ ! -f "${isohdpfx_path}" ]] && _die "💥 isolinux is not installed. On Ubuntu, install the 'isolinux' package."
fi
_log "👍 All required utilities are installed."

if [ ! -f "${source_iso}" ]; then
        _log "🌎 Downloading ISO image for Ubuntu ${image_type^}..."
        curl -NsSL "${download_url}/${download_iso}" -o "${source_iso}"
        _log "👍 Downloaded and saved to ${source_iso}"
else
        _log "☑️  Using existing ${source_iso} file."
        if [ ${gpg_verify} -eq 1 ]; then
                if [ "${source_iso}" != "${script_dir}/${original_iso}" ]; then
                        _log "⚠️ Automatic GPG verification is enabled. If the source ISO file is not the latest daily or release image, verification will fail!"
                fi
        fi
fi

if [ ${gpg_verify} -eq 1 ]; then
        if [ ! -f "${script_dir}/SHA256SUMS-${sha_suffix}" ]; then
                _log "🌎 Downloading SHA256SUMS & SHA256SUMS.gpg files..."
                curl -NsSL "${download_url}/SHA256SUMS" -o "${script_dir}/SHA256SUMS-${sha_suffix}"
                curl -NsSL "${download_url}/SHA256SUMS.gpg" -o "${script_dir}/SHA256SUMS-${sha_suffix}.gpg"
        else
                _log "☑️ Using existing SHA256SUMS-${sha_suffix} & SHA256SUMS-${sha_suffix}.gpg files."
        fi

        if [ ! -f "${script_dir}/${ubuntu_gpg_key_id}.keyring" ]; then
                _log "🌎 Downloading and saving Ubuntu signing key..."
                gpg -q --no-default-keyring --keyring "${script_dir}/${ubuntu_gpg_key_id}.keyring" --keyserver "hkp://keyserver.ubuntu.com" --recv-keys "${ubuntu_gpg_key_id}"
                _log "👍 Downloaded and saved to ${script_dir}/${ubuntu_gpg_key_id}.keyring"
        else
                _log "☑️ Using existing Ubuntu signing key saved in ${script_dir}/${ubuntu_gpg_key_id}.keyring"
        fi

        _log "🔐 Verifying ${source_iso} integrity and authenticity..."
        # gpg -q --keyring "${script_dir}/${ubuntu_gpg_key_id}.keyring" --verify "${script_dir}/SHA256SUMS-${sha_suffix}.gpg" "${script_dir}/SHA256SUMS-${sha_suffix}" 2>/dev/null
        # if [ $? -ne 0 ]; then
        #         rm -f "${script_dir}/${ubuntu_gpg_key_id}.keyring~"
        #         _die "👿 Verification of SHA256SUMS signature failed."
        # fi

        if ! gpg -q --keyring "${script_dir}/${ubuntu_gpg_key_id}.keyring" --verify "${script_dir}/SHA256SUMS-${sha_suffix}.gpg" "${script_dir}/SHA256SUMS-${sha_suffix}" 2>/dev/null; then
                rm -f "${script_dir}/${ubuntu_gpg_key_id}.keyring~"
                _die "👿 Verification of SHA256SUMS signature failed."
        fi

        rm -f "${script_dir}/${ubuntu_gpg_key_id}.keyring~"
        digest=$(sha256sum "${source_iso}" | cut -f1 -d ' ')
        set +e
        # grep -Fq "$digest" "${script_dir}/SHA256SUMS-${sha_suffix}"
        # if [ $? -eq 0 ]; then
        #         _log "👍 Verification succeeded."
        #         set -e
        # else
        #         _die "👿 Verification of ISO digest failed."
        # fi
        if ! grep -Fq "$digest" "${script_dir}/SHA256SUMS-${sha_suffix}"; then
                _log "👍 Verification succeeded."
                set -e
        else
                _die "👿 Verification of ISO digest failed."
        fi
else
        _log "🤞 Skipping verification of source ISO."
fi
_log "🔧 Extracting ISO image..."
xorriso -osirrox on -indev "${source_iso}" -extract / "${tmpdir}" &>/dev/null
chmod -R u+w "${tmpdir}"
rm -rf "${tmpdir}/"'[BOOT]'
_log "👍 Extracted to ${tmpdir}"

_log "🔎 Checking for ISO version..."
iso_version=$(head -n1 "${tmpdir}/md5sum.txt")
if grep -q -E "${isolinux_version//,/|}" <<< "${iso_version}"; then
  is_isolinux=true
  _log "🚩 Found 'isolinux' version"
fi

if [ ${use_hwe_kernel} -eq 1 ]; then
        if grep -q "hwe-vmlinuz" "${tmpdir}/boot/grub/grub.cfg"; then
                _log "☑️ Destination ISO will use HWE kernel."
                if [ ${is_isolinux} = true ]; then
                        sed -i -e 's|/casper/vmlinuz|/casper/hwe-vmlinuz|g' "${tmpdir}/isolinux/txt.cfg"
                        sed -i -e 's|/casper/initrd|/casper/hwe-initrd|g' "${tmpdir}/isolinux/txt.cfg"
                fi
                sed -i -e 's|/casper/vmlinuz|/casper/hwe-vmlinuz|g' "${tmpdir}/boot/grub/grub.cfg"
                sed -i -e 's|/casper/initrd|/casper/hwe-initrd|g' "${tmpdir}/boot/grub/grub.cfg"
                sed -i -e 's|/casper/vmlinuz|/casper/hwe-vmlinuz|g' "${tmpdir}/boot/grub/loopback.cfg"
                sed -i -e 's|/casper/initrd|/casper/hwe-initrd|g' "${tmpdir}/boot/grub/loopback.cfg"
        else
                _log "⚠️ This source ISO does not support the HWE kernel. Proceeding with the regular kernel."
        fi
fi

_log "🧩 Adding autoinstall parameter to kernel command line..."
if [ ${is_isolinux} = true ]; then
        sed -i -e 's/---/ autoinstall  ---/g' "${tmpdir}/isolinux/txt.cfg"
fi
sed -i -e 's/---/ autoinstall  ---/g' "${tmpdir}/boot/grub/grub.cfg"
sed -i -e 's/---/ autoinstall  ---/g' "${tmpdir}/boot/grub/loopback.cfg"
_log "👍 Added parameter to UEFI and BIOS kernel command lines."

if [ ${all_in_one} -eq 1 ]; then
        _log "🧩 Adding user-data and meta-data files..."
        mkdir "${tmpdir}/nocloud"
        cp "$user_data_file" "${tmpdir}/nocloud/user-data"
        if [ -n "${meta_data_file}" ]; then
                cp "$meta_data_file" "${tmpdir}/nocloud/meta-data"
        else
                touch "${tmpdir}/nocloud/meta-data"
        fi
        if [ ${is_isolinux} = true ]; then
                sed -i -e 's,---,ds=nocloud;s=/cdrom/nocloud/  --- net.ifnames=0 biosdevname=0 ipv6.disable=1 ,g' "${tmpdir}/isolinux/txt.cfg"
        fi
        sed -i -e 's,---,ds=nocloud\\\;s=/cdrom/nocloud/  --- net.ifnames=0 biosdevname=0 ipv6.disable=1 ,g' "${tmpdir}/boot/grub/grub.cfg"
        sed -i -e 's,---,ds=nocloud\\\;s=/cdrom/nocloud/  --- net.ifnames=0 biosdevname=0 ipv6.disable=1 ,g' "${tmpdir}/boot/grub/loopback.cfg"
        _log "👍 Added data and configured kernel command line."
fi

if [ ${md5_checksum} -eq 1 ]; then
        _log "👷 Updating ${tmpdir}/md5sum.txt with hashes of modified files..."
        md5=$(md5sum "${tmpdir}/boot/grub/grub.cfg" | cut -f1 -d ' ')
        sed -i -e 's,^.*[[:space:]] ./boot/grub/grub.cfg,'"$md5"'  ./boot/grub/grub.cfg,' "${tmpdir}/md5sum.txt"
        md5=$(md5sum "${tmpdir}/boot/grub/loopback.cfg" | cut -f1 -d ' ')
        sed -i -e 's,^.*[[:space:]] ./boot/grub/loopback.cfg,'"$md5"'  ./boot/grub/loopback.cfg,' "${tmpdir}/md5sum.txt"
        _log "👍 Updated hashes."
else
        _log "🗑️ Clearing MD5 hashes..."
        echo > "${tmpdir}/md5sum.txt"
        _log "👍 Cleared hashes."
fi

if [ ${is_isolinux} = false ]; then
        _log "📦 Extracting from origin ISO image EFI boot data..."
        7z e "${source_iso}" -o"${tmpdir}/boot/" '[BOOT]/1-Boot-NoEmul.img' &>/dev/null
        7z e "${source_iso}" -o"${tmpdir}/boot/" '[BOOT]/2-Boot-NoEmul.img' &>/dev/null
fi

_log "📦 Repackaging extracted files into an ISO image..."
cd "${tmpdir}"

if [ ${is_isolinux} = true ]; then
        xorriso -as mkisofs -r -V "${iso_label}" -J -b isolinux/isolinux.bin -c isolinux/boot.cat -no-emul-boot -boot-load-size 4 -isohybrid-mbr "${isohdpfx_path}" -boot-info-table -input-charset utf-8 -eltorito-alt-boot -e boot/grub/efi.img -no-emul-boot -isohybrid-gpt-basdat -o "${destination_iso}" . &>/dev/null
else
        xorriso -as mkisofs -r -V "${iso_label}" --grub2-mbr "${tmpdir}/boot/1-Boot-NoEmul.img" -partition_offset 16 --mbr-force-bootable -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "${tmpdir}/boot/2-Boot-NoEmul.img" -appended_part_as_gpt -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 -c "boot.cata_log" -b "boot/grub/i386-pc/eltorito.img" -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info -eltorito-alt-boot -e '--interval:appended_partition_2:::' -no-emul-boot -o "${destination_iso}" . &>/dev/null
fi

cd "$OLDPWD"
_log "👍 Repackaged into ${destination_iso}"

_die "✅ Completed." 0