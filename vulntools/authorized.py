"""Configuration-driven adapters for legitimately authorized vulnerability APIs.

The adapter deliberately does not encode undocumented AVD/CNNVD endpoints.  A data
provider supplies an HTTPS endpoint and a response mapping; credentials are read
from an environment variable and are never stored in the configuration or result.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote, urlparse

from .collectors import parse_exchange
from .models import SourceRecord


SCHEMA = "vulntools/authorized-api/v1"
SOURCES = {"avd", "cnnvd"}


def _pointer(document: Any, pointer: str) -> Any:
    """Resolve a small, standards-compatible JSON Pointer."""
    if pointer == "":
        return document
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        raise ValueError(f"Invalid JSON pointer: {pointer!r}")
    current = document
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                raise ValueError(f"JSON pointer does not exist: {pointer}")
            current = current[int(part)]
        elif isinstance(current, dict) and part in current:
            current = current[part]
        else:
            raise ValueError(f"JSON pointer does not exist: {pointer}")
    return current


def load_authorized_config(path_or_value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(path_or_value, Mapping):
        config = dict(path_or_value)
    else:
        config = json.loads(Path(path_or_value).read_text(encoding="utf-8-sig"))
    if config.get("schema") != SCHEMA:
        raise ValueError(f"Authorized API config must use {SCHEMA}")
    source = str(config.get("source", "")).casefold()
    if source not in SOURCES:
        raise ValueError("Authorized API source must be avd or cnnvd")
    endpoint = config.get("endpoint_template")
    if not isinstance(endpoint, str) or endpoint.count("{id}") != 1:
        raise ValueError("Authorized API endpoint_template must contain {id} exactly once")
    parsed = urlparse(endpoint.replace("{id}", "probe"))
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Authorized API endpoint must be credential-free HTTPS")
    response_format = config.get("response_format", "exchange")
    if response_format not in {"exchange", "mapped-json/v1"}:
        raise ValueError("Authorized API response_format must be exchange or mapped-json/v1")
    auth = config.get("auth") or {}
    if not isinstance(auth, dict):
        raise ValueError("Authorized API auth must be an object")
    if any(key in auth for key in ("token", "secret", "password", "api_key")):
        raise ValueError("Credentials cannot be stored in config; use auth.token_env")
    token_env = auth.get("token_env")
    if token_env is not None and (not isinstance(token_env, str) or not token_env.strip()):
        raise ValueError("auth.token_env must name a nonempty environment variable")
    header = auth.get("header", "Authorization")
    scheme = auth.get("scheme", "Bearer")
    if not isinstance(header, str) or not header.strip() or any(x in header for x in "\r\n:"):
        raise ValueError("auth.header is invalid")
    if not isinstance(scheme, str) or any(x in scheme for x in "\r\n"):
        raise ValueError("auth.scheme is invalid")
    static_headers = config.get("headers") or {}
    if not isinstance(static_headers, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) or any(x in key + value for x in "\r\n")
        for key, value in static_headers.items()
    ):
        raise ValueError("Authorized API headers must be a string map without line breaks")
    secret_names = {"authorization", "proxy-authorization", "x-api-key", "api-key"}
    if any(key.casefold() in secret_names for key in static_headers):
        raise ValueError("Secret headers must use auth.token_env, not static config")
    if response_format == "mapped-json/v1":
        mapping = config.get("mapping")
        if not isinstance(mapping, dict) or not isinstance(mapping.get("source_id"), str):
            raise ValueError("mapped-json/v1 requires mapping.source_id")
        fields = mapping.get("fields") or {}
        if not isinstance(fields, dict) or any(not isinstance(value, str) for value in fields.values()):
            raise ValueError("mapping.fields must map field names to JSON pointers")
    config["source"] = source
    config["response_format"] = response_format
    return config


def request_parts(config: Mapping[str, Any], identifier: str,
                  environ: Mapping[str, str] | None = None) -> tuple[str, dict[str, str], str]:
    identifier = identifier.strip()
    if not identifier:
        raise ValueError("Authorized API identifier cannot be empty")
    endpoint = str(config["endpoint_template"]).format(id=quote(identifier, safe=""))
    host = urlparse(endpoint).hostname
    if not host:
        raise ValueError("Authorized API endpoint has no host")
    headers = {"Accept": "application/json", **(config.get("headers") or {})}
    auth = config.get("auth") or {}
    token_env = auth.get("token_env")
    if token_env:
        env = os.environ if environ is None else environ
        token = env.get(token_env)
        if not token:
            raise ValueError(f"Required credential environment variable is not set: {token_env}")
        scheme = str(auth.get("scheme", "Bearer")).strip()
        headers[str(auth.get("header", "Authorization"))] = f"{scheme} {token}".strip()
    return endpoint, headers, host.casefold()


def _mapped_record(source: str, payload: Any, mapping: Mapping[str, Any], request_url: str) -> SourceRecord:
    if not isinstance(payload, dict):
        raise ValueError("Mapped authorized API response must resolve to an object")

    def optional(name: str, default: Any = None) -> Any:
        pointer = mapping.get(name)
        return _pointer(payload, pointer) if isinstance(pointer, str) else default

    source_id = _pointer(payload, mapping["source_id"])
    fields = {name: _pointer(payload, pointer) for name, pointer in (mapping.get("fields") or {}).items()}
    aliases = optional("aliases", [])
    references = optional("references", [])
    if isinstance(aliases, str):
        aliases = [aliases]
    if isinstance(references, str):
        references = [references]
    if not isinstance(aliases, list) or not isinstance(references, list):
        raise ValueError("Mapped aliases and references must resolve to a string or array")
    url = optional("url", request_url)
    status = optional("status", "active")
    updated = optional("source_updated_at")
    return SourceRecord(
        source, str(source_id), str(url), payload,
        aliases=[str(item) for item in aliases], fields=fields,
        references=[str(item) for item in references], status=str(status),
        source_updated_at=str(updated) if updated else None,
    )


def parse_authorized_response(config: Mapping[str, Any], response: Any, request_url: str,
                              requested_identifier: str) -> SourceRecord:
    payload = _pointer(response, str(config.get("record_pointer", "")))
    source = str(config["source"])
    if config["response_format"] == "exchange":
        if not isinstance(payload, dict):
            raise ValueError("Exchange authorized API response must resolve to an object")
        record = parse_exchange(source, payload)
    else:
        record = _mapped_record(source, payload, config["mapping"], request_url)
    expected_prefix = source.upper() + "-"
    if requested_identifier.upper().startswith(expected_prefix) and record.source_id.casefold() != requested_identifier.casefold():
        raise ValueError("Authorized API response identifier does not match the requested identifier")
    return record


def fetch_authorized_record(config_path: str | Path | Mapping[str, Any], identifier: str, *,
                            client: Any | None = None,
                            environ: Mapping[str, str] | None = None) -> SourceRecord:
    """Fetch one record through an explicitly configured, authorized JSON API."""
    config = load_authorized_config(config_path)
    url, headers, host = request_parts(config, identifier, environ)
    if client is None:
        # Delayed import avoids a module cycle: collection imports this function only on use.
        from .collection import HttpClient
        client = HttpClient(allowed_hosts={host})
    response = client.get_json(url, headers=headers)
    return parse_authorized_response(config, response, url, identifier)
