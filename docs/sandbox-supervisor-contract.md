# VM Supervisor Contract

The sandbox agent intentionally does not own hypervisor privileges. It invokes one root-owned, SHA-256-pinned supervisor executable with `shell=False`, a minimal environment, and one of these commands:

```text
supervisor run --spec /absolute/run-spec.json
supervisor destroy --run-id run_<32 hex>
supervisor acceptance --state-dir /absolute/state
```

The organization deploying the execution node must supply and independently review this executable. It may be a narrow client for a privileged Firecracker service; it must not be a general shell wrapper.

The repository supplies commissioning helpers (`guest_monitor.canary_guest_request`, `guest_channel.request_guest` and `decode_guest_response`) plus a canary-only guest service. They provide no VM lifecycle, cgroups, external watchdog or privileged service. See [node assets](sandbox-node-assets.md); none of their fixture tests may be used as the nine actual-node acceptance results.

## `run`

The JSON spec uses schema `vulntools/supervisor-run/v1` and contains the run ID, host staging sample path and digest, artifact directory, pinned kernel/rootfs paths, and validated sandbox policy. The supervisor must:

1. create a fresh Firecracker microVM using KVM and jailer;
2. use the pinned read-only base plus a per-run copy-on-write overlay;
3. configure no network device at all;
4. configure host cgroup v2 CPU, memory and PID limits before guest execution;
5. transfer the sample through a bounded guest channel, never a host filesystem mount;
6. start the guest monitor before the sample and fail closed if it exits;
7. enforce a host-owned watchdog independent of both agent and guest;
8. return only after the VM is stopped and the overlay has been removed;
9. write only `events.jsonl`, `stdout.txt`, `stderr.txt`, and `result.json`;
10. emit one JSON object on stdout containing a terminal `status` and matching `run_id`.

All diagnostics go to stderr. The process must return nonzero on incomplete cleanup, monitor loss, protocol errors, artifact overflow, or digest mismatch.

## `destroy`

Destruction is idempotent. It kills the VM/cgroup, deletes the overlay and runtime sockets, verifies absence, and returns:

```json
{"run_id":"run_...","destroyed":true}
```

If absence cannot be verified it returns nonzero. The agent then writes `QUARANTINED` and rejects new submissions.

## `acceptance`

This command runs harmless probes on the real node and returns an `acceptance_tests` object. It must not report a test as passed from configuration alone. Required tests are:

- `network_blocked`: no NIC/default route; DNS, TCP and UDP probes fail and host observation sees no egress;
- `host_fs_hidden`: a randomized host marker and host block devices are unavailable in the guest;
- `timeout_kill`: a benign infinite loop is terminated by the host deadline;
- `resource_kill`: controlled memory/PID allocation is terminated by cgroup limits;
- `monitor_fail_closed`: stopping the monitor prevents or terminates sample execution;
- `overlay_destroyed`: a guest marker and the overlay disappear after teardown;
- `watchdog_survives_disconnect`: terminating the control client does not disable teardown;
- `orphan_recovery`: a simulated agent restart leaves no VM, cgroup, socket, or overlay;
- `artifact_integrity`: traversal, duplicate, oversized, corrupt and cross-run artifacts are rejected.

The CLI signs the returned record with the attestation key. A record is valid for at most 30 days and is bound to the exact supervisor, guest image, and kernel digests.
