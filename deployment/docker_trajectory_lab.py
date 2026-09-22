"""Harmless deterministic security canaries executed inside a locked-down container.

The host streams JSONL scenarios on stdin and receives one JSON result per line.
There is no network access, no target discovery, and no arbitrary user-supplied code.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import html
import json
import os
import sqlite3
import subprocess
import sys
from typing import Any, Callable


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _runtime_evidence() -> dict[str, Any]:
    status: dict[str, str] = {}
    try:
        for line in open("/proc/self/status", encoding="utf-8"):
            key, _, value = line.partition(":")
            if key in {"CapEff", "NoNewPrivs"}:
                status[key] = value.strip()
    except OSError:
        pass
    root_write_blocked = False
    root_write_errno = None
    try:
        with open("/vulntools-readonly-probe", "w", encoding="utf-8") as stream:
            stream.write("unexpected")
    except OSError as exc:
        root_write_blocked = True
        root_write_errno = exc.errno
    interfaces = sorted(os.listdir("/sys/class/net")) if os.path.isdir("/sys/class/net") else []
    return {
        "container": True,
        "network_expected": "none",
        "interfaces": interfaces,
        "uid": os.getuid() if hasattr(os, "getuid") else None,
        "gid": os.getgid() if hasattr(os, "getgid") else None,
        "cap_eff": status.get("CapEff"),
        "no_new_privileges": status.get("NoNewPrivs") == "1",
        "root_write_blocked": root_write_blocked,
        "root_write_errno": root_write_errno,
    }


def _xss(canary: str) -> dict[str, Any]:
    marker = f'<span data-vulntools-canary="{canary}">safe</span>'
    vulnerable = f"<article>{marker}</article>"
    safe = f"<article>{html.escape(marker)}</article>"
    passed = marker in vulnerable and marker not in safe
    return {
        "passed": passed,
        "observation": "The synthetic HTML sink preserved an untrusted markup canary without output encoding.",
        "proof": {"unsafe_marker_present": marker in vulnerable, "encoded_control_blocked": marker not in safe},
    }


def _sql_injection(canary: str) -> dict[str, Any]:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(
            "CREATE TABLE users(name TEXT, role TEXT);"
            "INSERT INTO users VALUES ('guest','reader'),('admin','administrator');"
        )
        probe = "guest' OR '1'='1"
        vulnerable = connection.execute(
            "SELECT role FROM users WHERE name='" + probe + "'"
        ).fetchall()
        control = connection.execute("SELECT role FROM users WHERE name=?", (probe,)).fetchall()
        passed = len(vulnerable) == 2 and not control
        return {
            "passed": passed,
            "observation": "The in-memory lab query returned additional rows only through the concatenated SQL path.",
            "proof": {"unsafe_row_count": len(vulnerable), "parameterized_row_count": len(control)},
        }
    finally:
        connection.close()


def _command_injection(canary: str) -> dict[str, Any]:
    marker = "CANARY-" + canary
    command = "printf BASE; printf " + marker
    completed = subprocess.run(
        ["/bin/sh", "-c", command],
        check=False,
        capture_output=True,
        text=True,
        timeout=2,
        env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
        cwd="/tmp",
    )
    output = completed.stdout
    passed = completed.returncode == 0 and marker in output
    return {
        "passed": passed,
        "observation": "The isolated shell canary showed that command text reached a shell execution boundary.",
        "proof": {"return_code": completed.returncode, "canary_seen": marker in output},
    }


def _ssrf(canary: str) -> dict[str, Any]:
    internal_url = f"http://metadata.local/{canary}"
    internal_routes = {internal_url: "METADATA-CANARY-" + canary}

    def vulnerable_fetch(url: str) -> str:
        return internal_routes.get(url, "external-disabled")

    response = vulnerable_fetch(internal_url)
    passed = response == "METADATA-CANARY-" + canary
    return {
        "passed": passed,
        "observation": "The synthetic URL fetcher reached an internal-only in-process metadata route from untrusted input.",
        "proof": {"internal_route_reached": passed, "docker_network": "none"},
    }


def _csrf(canary: str) -> dict[str, Any]:
    state = {"owner": "alice", "email": "alice@example.test"}

    def vulnerable_update(actor: str, new_email: str, csrf_token: str | None) -> None:
        del actor, csrf_token
        state["email"] = new_email

    vulnerable_update("alice", f"{canary}@example.test", None)
    passed = state["email"] == f"{canary}@example.test"
    return {
        "passed": passed,
        "observation": "The synthetic state-changing handler accepted a request without a CSRF token.",
        "proof": {"state_changed": passed, "token_supplied": False},
    }


def _parameter_tampering(canary: str) -> dict[str, Any]:
    order = {"sku": "LAB", "server_price": 100, "charged": 100}
    submitted = {"price": int(canary[:2], 16) % 10 + 1}
    order["charged"] = submitted["price"]
    passed = order["charged"] != order["server_price"]
    return {
        "passed": passed,
        "observation": "The synthetic checkout trusted a client-controlled price instead of the server-side value.",
        "proof": {"server_price": 100, "charged_price": order["charged"]},
    }


def _mass_assignment(canary: str) -> dict[str, Any]:
    account = {"display_name": "guest", "role": "user"}
    submitted = {"display_name": "user-" + canary[:8], "role": "admin"}
    account.update(submitted)
    passed = account["role"] == "admin"
    return {
        "passed": passed,
        "observation": "The synthetic object binder accepted a privileged field that was not allow-listed.",
        "proof": {"privileged_field_bound": passed, "final_role": account["role"]},
    }


def _authorization_replay(canary: str) -> dict[str, Any]:
    operation = {"owner": "alice", "nonce": canary, "used": False}

    def vulnerable_replay(actor: str, nonce: str) -> bool:
        if nonce != operation["nonce"]:
            return False
        operation["used"] = True
        return True

    accepted = vulnerable_replay("bob", canary)
    passed = accepted and operation["owner"] != "bob"
    return {
        "passed": passed,
        "observation": "The synthetic authorization handler accepted another actor's operation nonce.",
        "proof": {"cross_actor_replay_accepted": passed, "operation_used": operation["used"]},
    }


def _duplicate_submission(canary: str) -> dict[str, Any]:
    del canary
    account = {"credits": 0}

    def vulnerable_submit() -> None:
        account["credits"] += 1

    vulnerable_submit()
    vulnerable_submit()
    passed = account["credits"] == 2
    return {
        "passed": passed,
        "observation": "The synthetic handler applied the same logical operation twice without idempotency enforcement.",
        "proof": {"application_count": account["credits"], "expected_idempotent_count": 1},
    }


def _workflow_order_bypass(canary: str) -> dict[str, Any]:
    workflow = {"approved": False, "completed": False, "reference": canary}

    def vulnerable_complete() -> None:
        workflow["completed"] = True

    vulnerable_complete()
    passed = workflow["completed"] and not workflow["approved"]
    return {
        "passed": passed,
        "observation": "The synthetic workflow accepted completion before its approval transition.",
        "proof": {"completed": workflow["completed"], "approved": workflow["approved"]},
    }


RUNNERS: dict[str, Callable[[str], dict[str, Any]]] = {
    "xss": _xss,
    "sql_injection": _sql_injection,
    "command_injection": _command_injection,
    "ssrf": _ssrf,
    "csrf": _csrf,
    "parameter_tampering": _parameter_tampering,
    "mass_assignment": _mass_assignment,
    "authorization_replay": _authorization_replay,
    "duplicate_submission": _duplicate_submission,
    "workflow_order_bypass": _workflow_order_bypass,
}


def _resolve_obstacle(obstacle: str, canary: str) -> dict[str, Any]:
    """Exercise a harmless, deterministic recovery branch before the canary check."""
    if obstacle == "none":
        return {
            "observed": False,
            "recovery_action": "No recovery was required; continue with the authorized lab check.",
            "recovery_verified": True,
            "proof": {"precondition_ready": True},
        }
    if obstacle == "session_expired":
        session = {"valid": False, "generation": 1}
        initially_blocked = not session["valid"]
        session.update(valid=True, generation=2)
        return {
            "observed": initially_blocked,
            "recovery_action": "Refresh the disposable lab session and bind the same canary to it.",
            "recovery_verified": session["valid"] and session["generation"] == 2,
            "proof": {"initial_generation": 1, "refreshed_generation": session["generation"]},
        }
    if obstacle == "field_alias":
        schema = {"public_name": "canonical_test_field"}
        resolved = schema.get("public_name")
        return {
            "observed": resolved != "public_name",
            "recovery_action": "Resolve the documented field alias to the canonical synthetic test field.",
            "recovery_verified": resolved == "canonical_test_field",
            "proof": {"requested_field": "public_name", "resolved_field": resolved},
        }
    if obstacle == "input_filter":
        raw_marker = "<blocked>"
        canonical_marker = "CANARY-" + canary
        raw_rejected = "<" in raw_marker
        canonical_accepted = canonical_marker.startswith("CANARY-") and "<" not in canonical_marker
        return {
            "observed": raw_rejected,
            "recovery_action": "Use the lab-documented canonical canary representation without bypassing a real filter.",
            "recovery_verified": canonical_accepted,
            "proof": {"raw_variant_rejected": raw_rejected, "canonical_variant_accepted": canonical_accepted},
        }
    if obstacle == "state_version":
        state = {"current": 2, "requested": 1}
        initially_blocked = state["requested"] != state["current"]
        state["requested"] = state["current"]
        return {
            "observed": initially_blocked,
            "recovery_action": "Reload the disposable workflow state and retry against its current version.",
            "recovery_verified": state["requested"] == state["current"],
            "proof": {"stale_version": 1, "current_version": state["current"]},
        }
    raise ValueError("unsupported obstacle")


def run_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    started_at = _now()
    scenario_id = str(scenario["scenario_id"])
    vulnerability_type = str(scenario["vulnerability_type"])
    canary = str(scenario["canary"])
    if vulnerability_type not in RUNNERS:
        raise ValueError("unsupported vulnerability_type")
    obstacle = str(scenario["obstacle"])
    recovery = _resolve_obstacle(obstacle, canary)
    blocked_initial = bool(recovery["observed"])
    result = RUNNERS[vulnerability_type](canary)
    passed = bool(result["passed"]) and bool(recovery["recovery_verified"])
    evidence_digest = _digest(
        f"{scenario_id}|{vulnerability_type}|{canary}|{'passed' if passed else 'failed'}"
    )
    return {
        "schema": "vulntools/docker-trajectory-result/v1",
        "scenario_id": scenario_id,
        "scenario_sha256": _digest(_canonical(scenario)),
        "vulnerability_type": vulnerability_type,
        "category": scenario["category"],
        "case_index": scenario["case_index"],
        "variant": scenario["variant"],
        "obstacle": obstacle,
        "blocked_initial": blocked_initial,
        "recovered": bool(recovery["recovery_verified"]),
        "obstacle_observation": recovery["proof"],
        "recovery_action": recovery["recovery_action"],
        "recovery_verified": recovery["recovery_verified"],
        "success": passed,
        "observation": result["observation"],
        "proof": result["proof"],
        "evidence_digest": evidence_digest,
        "expected_digest": scenario["expected_digest"],
        "started_at": started_at,
        "completed_at": _now(),
        "runtime": _runtime_evidence(),
    }


def main() -> int:
    for line_number, line in enumerate(sys.stdin, 1):
        if not line.strip():
            continue
        try:
            scenario = json.loads(line)
            result = run_scenario(scenario)
        except Exception as exc:  # return an evidence-bound failed row instead of hiding it
            result = {
                "schema": "vulntools/docker-trajectory-result/v1",
                "scenario_id": f"invalid-line-{line_number}",
                "success": False,
                "error": f"{type(exc).__name__}: {exc}",
                "completed_at": _now(),
            }
        sys.stdout.write(_canonical(result) + "\n")
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
