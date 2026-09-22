"""Guest-only control: dummy in-memory data; no network, files or subprocesses."""
import json

PROBE_NONCE = "__PROBE_NONCE__"


def main():
    record = {"owner": "owner", "body": "CANARY_ONLY"}
    actor = "observer"
    allowed = actor == record["owner"]
    response = record["body"] if allowed else None
    print(json.dumps({"schema": "vulntools/canary-observation/v1", "case_id": "authz-canary",
                      "nonce": PROBE_NONCE, "variant": "boundary_enforced", "actor": actor,
                      "owner": record["owner"], "access_allowed": allowed,
                      "marker_observed": response == "CANARY_ONLY"}, sort_keys=True))


if __name__ == "__main__":
    main()
