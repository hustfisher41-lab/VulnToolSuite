#!/bin/bash
# Admin-run offline bootstrap ONLY on a dedicated node. Never enables execution.
set -euo pipefail
if [[ $# != 3 || "$1" != "--confirm-dedicated-node" || "$2" != "--wheelhouse" ]]; then
  echo 'Usage: bash deployment/install-sandbox-node.sh --confirm-dedicated-node --wheelhouse /approved/wheels' >&2
  exit 2
fi
if [[ "$EUID" != 0 || "$(uname -s)" != Linux || ! -c /dev/kvm ]]; then
  echo 'Root administration on a dedicated Linux/KVM node is required' >&2
  exit 2
fi
if [[ -f /.dockerenv || -f /run/.containerenv ]] || [[ "$(uname -r)" == *[Mm]icrosoft* ]]; then
  echo 'WSL/container hosts are not accepted' >&2
  exit 2
fi
bundle_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
wheel_dir="$3"
[[ -d "$wheel_dir" ]] || { echo 'Offline wheelhouse missing' >&2; exit 2; }
[[ ! -e /opt/vulntools/venv && ! -e /etc/vulntools/sandbox-agent.json ]] || {
  echo 'Existing installation/config found; use a reviewed upgrade process, not this bootstrap' >&2; exit 2;
}
python3 "$bundle_dir/deployment/verify-node-bundle.py" "$bundle_dir"
getent passwd vulntools-sandbox >/dev/null || useradd --system --home-dir /var/lib/vulntools-sandbox --shell /usr/sbin/nologin vulntools-sandbox
install -d -m 0755 /opt/vulntools
install -d -m 0750 -o root -g vulntools-sandbox /etc/vulntools /etc/vulntools/pki
install -d -m 0700 -o vulntools-sandbox -g vulntools-sandbox /var/lib/vulntools-sandbox
python3 -m venv /opt/vulntools/venv
/opt/vulntools/venv/bin/python -m pip install --no-index --find-links "$wheel_dir" "$bundle_dir/code[api]"
install -m 0640 -o root -g vulntools-sandbox "$bundle_dir/examples/sandbox-agent.example.json" /etc/vulntools/sandbox-agent.json
install -m 0644 "$bundle_dir/deployment/systemd/vulntools-sandbox-agent.service" /etc/systemd/system/vulntools-sandbox-agent.service
echo 'Bootstrap installed; service NOT enabled/started, no samples executed.'
echo 'Supply reviewed supervisor/service, guest image/kernel, mTLS and secrets; pin digests and complete acceptance before activation.'
