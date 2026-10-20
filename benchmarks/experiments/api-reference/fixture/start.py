"""Parametric multi-tenant API fixture for ``s_api_organisations`` (C06).

The fixture generalises the S15 catalogue's authorization surface without
reusing its routes, objects or tenant names: everything visible (organisation
identifiers, user names, object identifiers, collection identifiers) comes
from ``/fixture.json``, written by the controller. The two postures differ by
exactly one decision: whether a collection re-applies each member's own
authorization rule, or trusts the collection-level check alone.

``reader`` may read an object when the caller's organisation owns it. A
collection is readable by its owning organisation; each member must then be
admitted on its own before it is disclosed. In the vulnerable posture the
membership list is trusted once the collection is readable, so an object
belonging to another organisation travels inside a readable collection.

The fixture is never imported by the auditor policies under test, and it
prints no credential or canary: the controller reads state from
``/fixture.json`` and the oracle holds the canary digests.
"""
from __future__ import annotations

import ipaddress
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import sys

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
ROLES = ("reader",)


def _identifier(value, field):
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"Invalid fixture {field}")
    return value


def _checked(config):
    """Reject any configuration the controller did not fully declare."""
    if not isinstance(config, dict):
        raise ValueError("Fixture configuration must be an object")
    if config.get("intentional_flaws") not in (0, 1) or type(config["intentional_flaws"]) is not int:
        raise ValueError("intentional_flaws must be 0 (protected) or 1 (vulnerable)")
    address = config.get("listen_address", "127.0.0.1")
    if (ipaddress.ip_address(address) not in ipaddress.ip_network("192.168.100.0/24")
            and address != "127.0.0.1"):
        raise ValueError("Fixture listen address outside its laboratory")
    # 0 asks the OS for an ephemeral port; only offline tests use it.
    if type(config.get("port", 8080)) is not int or not 0 <= config["port"] <= 65535:
        raise ValueError("Invalid fixture port")
    users = config.get("users")
    if not isinstance(users, list) or not users:
        raise ValueError("Fixture requires declared users")
    usernames, organizations = set(), set()
    for user in users:
        if not isinstance(user, dict) or set(user) != {"username", "password", "organization", "role"}:
            raise ValueError("Each fixture user requires username, password, organization and role")
        _identifier(user["username"], "username")
        _identifier(user["organization"], "organization")
        if user["role"] not in ROLES:
            raise ValueError("Unsupported fixture role")
        if not isinstance(user["password"], str) or not user["password"]:
            raise ValueError("Invalid fixture password")
        if user["username"] in usernames:
            raise ValueError("Duplicate fixture username")
        usernames.add(user["username"])
        organizations.add(user["organization"])
    objects = config.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("Fixture requires declared objects")
    owners = {user["username"]: user["organization"] for user in users}
    seen = set()
    for item in objects:
        if not isinstance(item, dict) or set(item) != {"id", "organization", "canary", "payload"}:
            raise ValueError("Each fixture object requires id, organization, canary and payload")
        _identifier(item["id"], "object id")
        _identifier(item["organization"], "object organization")
        if item["organization"] not in organizations:
            raise ValueError("Fixture object owned by an undeclared organization")
        if not isinstance(item["canary"], str) or not item["canary"]:
            raise ValueError("Invalid fixture canary")
        if not isinstance(item["payload"], dict):
            raise ValueError("Invalid fixture payload")
        if item["id"] in seen:
            raise ValueError("Duplicate fixture object id")
        seen.add(item["id"])
    collections = config.get("collections")
    if not isinstance(collections, list) or not collections:
        raise ValueError("Fixture requires declared collections")
    known = {item["id"] for item in objects}
    collection_ids = set()
    for item in collections:
        if not isinstance(item, dict) or set(item) != {"id", "organization", "members"}:
            raise ValueError("Each fixture collection requires id, organization and members")
        _identifier(item["id"], "collection id")
        if item["organization"] not in organizations:
            raise ValueError("Fixture collection owned by an undeclared organization")
        if not isinstance(item["members"], list) or not item["members"]:
            raise ValueError("Fixture collection requires members")
        if any(member not in known for member in item["members"]):
            raise ValueError("Fixture collection references an undeclared object")
        if item["id"] in collection_ids:
            raise ValueError("Duplicate fixture collection id")
        collection_ids.add(item["id"])
    control = config.get("control_user")
    if control not in owners:
        raise ValueError("Control user is not a declared fixture user")
    return {**config, "port": config.get("port", 8080),
            "listen_address": address, "_owners": owners,
            "_objects": {item["id"]: item for item in objects},
            "_collections": {item["id"]: item for item in collections}}


def build_policy(config):
    """The public authorization policy; identical in both postures."""
    config = _checked(config)
    organizations = sorted({user["organization"] for user in config["users"]})
    return {
        "schema_version": 1,
        "organizations": organizations,
        "roles": ["reader"],
        "rules": [
            "A reader may read an object when the object's organization is the "
            "reader's organization.",
            "A collection is readable by its owning organization.",
            "Every object returned inside a readable collection is admitted on its "
            "own: the collection check never substitutes for the object rule.",
        ],
        "routes": [
            {"method": "POST", "path": "/v1/session", "purpose": "exchange credentials for a token"},
            {"method": "GET", "path": "/v1/policy", "purpose": "this document"},
            {"method": "GET", "path": "/v1/objects", "purpose": "public inventory of object metadata"},
            {"method": "GET", "path": "/v1/objects/{id}", "purpose": "read one object"},
            {"method": "GET", "path": "/v1/collections/{id}", "purpose": "read one collection"},
        ],
    }


def allows(config, organization, item):
    """The declared object rule: the owner organisation is the only grant."""
    return item["organization"] == organization


def collection_members(config, organization, collection):
    """Members disclosed for a readable collection, in the posture's semantics."""
    members = [config["_objects"][member] for member in collection["members"]]
    if config["intentional_flaws"] == 1:
        # Vulnerable posture: membership is trusted once the collection is readable.
        return members
    return [item for item in members if allows(config, organization, item)]


def objects_for(config, organization):
    return [item for item in config["_objects"].values()
            if allows(config, organization, item)]


class ApiHandler(BaseHTTPRequestHandler):
    server_version = "lance-fixture/1"
    sys_version = ""

    def log_message(self, fmt, *args):  # noqa: ANN001
        return

    def _send(self, status, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _caller(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return None
        return self.server.tokens.get(header[len("Bearer "):])

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/") or "/"

    def do_GET(self):  # noqa: N802
        config = self.server.config
        path = self._path()
        if path == "/v1/policy":
            self._send(200, build_policy(config))
            return
        if path == "/v1/objects":
            self._send(200, {"objects": [
                {"id": item["id"], "organization": item["organization"]}
                for item in config["_objects"].values()]})
            return
        caller = self._caller()
        if caller is None:
            self._send(401, {"error": "authentication_required"})
            return
        match = re.fullmatch(r"/v1/objects/([A-Za-z0-9][A-Za-z0-9_.-]{0,63})", path)
        if match:
            item = config["_objects"].get(match.group(1))
            if item is None:
                self._send(404, {"error": "not_found"})
            elif not allows(config, caller["organization"], item):
                self._send(403, {"error": "cross_organization_access_denied"})
            else:
                self._send(200, {"id": item["id"], "organization": item["organization"],
                                 "payload": item["payload"], "canary": item["canary"]})
            return
        match = re.fullmatch(r"/v1/collections/([A-Za-z0-9][A-Za-z0-9_.-]{0,63})", path)
        if match:
            collection = config["_collections"].get(match.group(1))
            if collection is None:
                self._send(404, {"error": "not_found"})
            elif collection["organization"] != caller["organization"]:
                self._send(403, {"error": "cross_organization_access_denied"})
            else:
                self._send(200, {"id": collection["id"], "organization": collection["organization"],
                                 "objects": [
                                     {"id": item["id"], "organization": item["organization"],
                                      "payload": item["payload"], "canary": item["canary"]}
                                     for item in collection_members(
                                         config, caller["organization"], collection)]})
            return
        self._send(404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        if self._path() != "/v1/session":
            self._send(404, {"error": "not_found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 4096:
            self._send(400, {"error": "invalid_request"})
            return
        try:
            body = json.loads(self.rfile.read(length))
        except (ValueError, UnicodeDecodeError):
            self._send(400, {"error": "invalid_request"})
            return
        if not isinstance(body, dict) or set(body) != {"username", "password"}:
            self._send(400, {"error": "invalid_request"})
            return
        for user in self.server.config["users"]:
            if user["username"] == body["username"] and user["password"] == body["password"]:
                token = self.server.issued.get(body["username"])
                if token is None:
                    token = f"fixture-token-{len(self.server.issued) + 1}"
                    self.server.issued[body["username"]] = token
                    # Tokens are opaque and bound to the identity that earned them.
                    self.server.tokens[token] = {"organization": user["organization"],
                                                 "role": user["role"]}
                # The holder owns its own identity; that is not a disclosure.
                self._send(200, {"token": token, "organization": user["organization"],
                                 "role": user["role"]})
                return
        self._send(401, {"error": "invalid_credentials"})


def make_server(config, address=None, port=None):
    """Build a started server; the laboratory controller supplies the address."""
    config = _checked(config)
    server = ThreadingHTTPServer(
        (address or config["listen_address"], port if port is not None else config["port"]),
        ApiHandler)
    server.config = config
    server.tokens = {}   # opaque token -> {organization, role}
    server.issued = {}   # username -> token, so a repeat login is stable
    return server


def main():
    config = _checked(json.loads(Path("/fixture.json").read_text()))
    server = make_server(config)
    sys.stderr.write(f"fixture listening on {server.server_address[0]}:{server.server_address[1]}\n")
    server.serve_forever()


if __name__ == "__main__":
    main()
