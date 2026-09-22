# Sandbox deployment runbook

The project now supplies bounded vsock transport, a guest-only/canary-only strace monitor, read-only node diagnostics and offline deployment bundle export. See [node assets](sandbox-node-assets.md). These are reference deployment components, not an installed privileged VM launcher or actual-node isolation certification.

## Boundary

Use a dedicated Linux execution node with hardware virtualization and `/dev/kvm`. Do not deploy it on a developer workstation or place secrets, source repositories, user home directories, production credentials, or unrelated workloads on the node. Linux user-mode samples are the only initial workload. Windows and kernel-level samples require separate Hyper-V/full-VM or high-risk pools and distinct backend identities.

The repository supplies the coordinator, hardened control agent, persistent state/recovery logic, signed attestation, acceptance-record workflow, and supervisor contract. Hardware, the guest image and the reviewed Firecracker supervisor are deployment assets and cannot be created or certified on the Windows development host.

## Provisioning order

1. Enable KVM/IOMMU in firmware and install a supported Firecracker plus jailer release.
2. Patch host firmware, microcode, kernel and Firecracker. Disable swap or use organization-approved encrypted swap.
3. Create a dedicated `vulntools-sandbox` account with no interactive login.
4. Install the agent in `/opt/vulntools/venv`; install the reviewed supervisor as a root-owned, non-writable executable in `/usr/local/libexec`.
5. Install immutable guest kernel/rootfs files. The guest contains only the monitor/runner and required libraries, uses a non-root sample UID, and starts no network service.
6. Calculate and place all three SHA-256 digests in `sandbox-agent.json` based on the example configuration.
7. Put the bearer token and attestation key only in root-readable `/etc/vulntools/sandbox-agent.env`:

   ```text
   VULNTOOLS_SANDBOX_TOKEN=<at least 24 random characters>
   VULNTOOLS_ATTESTATION_KEY=<at least 32 random bytes>
   ```

8. Issue a server certificate and client certificates from a private CA. Do not reuse a public web certificate CA as the client CA.
9. Run the acceptance command locally on the node:

   ```bash
   vulntools sandbox-acceptance \
     --config /etc/vulntools/sandbox-agent.json \
     --output /var/lib/vulntools-sandbox/acceptance.json
   ```

10. Add `acceptance_file` to the config, install the systemd unit, then start the service. Place a network firewall allowlist in front of port 9443 even though mTLS and bearer authentication are also required.

## Verification

From an authorized coordinator:

```powershell
$env:SANDBOX_TOKEN = '<short-lived token>'
$env:SANDBOX_ATTESTATION_KEY = '<shared verification key>'
python -m vulntools sandbox-run `
  --policy examples/sandbox-policy.json `
  --sample path/to/harmless-fixture `
  --output output/sandbox/fixture `
  --backend-url https://sandbox-linux-01.internal:9443 `
  --ca-file certs/agent-ca.pem `
  --cert-file certs/client.pem `
  --key-file certs/client-key.pem `
  --token-env SANDBOX_TOKEN `
  --attestation-key-env SANDBOX_ATTESTATION_KEY
```

Do not use a real PoC for commissioning. Confirm the returned backend and attestation IDs, matching sample digest, terminal status, `destroyed=true`, event run ID, and artifact hashes.

## Operations

- Rotate bearer tokens, mTLS certificates and the attestation key independently.
- Re-run acceptance after any host, kernel, Firecracker, supervisor, guest-image or policy change and at least every 30 days.
- Monitor `agent.sqlite`, service logs, free disk, KVM errors and the `QUARANTINED` marker.
- A destruction failure is a node incident. Stop scheduling, inspect and rebuild the node; do not merely delete the marker.
- Rebuild the node from clean infrastructure regularly. Never promote a high-risk node back into the normal pool without reprovisioning.
- Retained host artifacts are removed after the configured interval; export required evidence to an approved immutable store before then.
