"""Guest-only canary: dummy in-memory data; no network, files or subprocesses."""
import json

PROBE_NONCE = "__PROBE_NONCE__"


def main():
    record = {"owner": "owner", "body": "CANARY_ONLY"}
    actor = "observer"
    # Deliberately missing ownership check in a synthetic, in-memory fixture.
    response = record["body"]
    print(json.dumps({"schema": "vulntools/canary-observation/v1", "case_id": "authz-canary",
                      "nonce": PROBE_NONCE, "variant": "boundary_missing", "actor": actor,
                      "owner": record["owner"], "access_allowed": True,
                      "marker_observed": response == "CANARY_ONLY"}, sort_keys=True))


if __name__ == "__main__":
    main()
