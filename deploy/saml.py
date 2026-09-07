#!/usr/bin/env python3
"""P2b — Sonar SAML against https://auth.qa.guru.

Secrets stay in ~/.config (mode 600). Nothing here is printed.

  python3 deploy/saml.py inventory
  python3 deploy/saml.py ensure-groups
  python3 deploy/saml.py seed-idp
  python3 deploy/saml.py configure
  python3 deploy/saml.py verify
  python3 deploy/saml.py login-check          # SAML round-trip, no browser
  python3 deploy/saml.py break-glass          # stop Keycloak, local admin still works, start it
"""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any

try:
    import certifi
except ImportError:
    certifi = None  # type: ignore[assignment]

SONAR_URL = os.environ.get("SONAR_URL", "https://sonar.qa.guru").rstrip("/")
AUTH_URL = os.environ.get("AUTH_URL", "https://auth.qa.guru").rstrip("/")
REALM = os.environ.get("REALM", "qaguru")
SONAR_TOKEN_FILE = Path(os.environ.get("SONAR_ADMIN_TOKEN_FILE", Path.home() / ".config/sonar/admin-token"))
SONAR_ADMIN_PASSWORD_FILE = Path.home() / ".config/sonar/admin.password"
AUTH_ENV_FILE = Path(os.environ.get("AUTH_ENV", Path.home() / ".config/auth-qa-guru/keycloak.env"))
PILOT_ENV_FILE = Path(os.environ.get("PILOT_ENV", Path.home() / ".config/auth-qa-guru/pilot.env"))
INV_DIR = Path.home() / ".config/sonar/p2b-inventory"

STAFF_GROUP = "staff"
STUDENTS_GROUP = "students"
SAML_CLIENT_ID = "sonar"
SAML_PROVIDER_NAME = "QA Guru"
SAML_LOGIN_ATTR = "login"
SAML_NAME_ATTR = "name"
SAML_EMAIL_ATTR = "email"
SAML_GROUP_ATTR = "groups"

STAFF_GLOBAL_PERMS = ("admin", "gateadmin", "profileadmin", "provisioning")
TEMPLATE_NAME = "Default template"
STAFF_TEMPLATE_PERMS = ("admin",)
STUDENTS_TEMPLATE_PERMS = ("user", "codeviewer", "issueadmin", "securityhotspotadmin")

PILOT_PEOPLE = (
    {
        "env_user": "PILOT_STAFF_USERNAME",
        "env_pass": "PILOT_STAFF_PASSWORD",
        "env_email": "PILOT_STAFF_EMAIL",
        "username": "staff-pilot",
        "email": "staff-pilot@qa.guru",
        "firstName": "Staff",
        "lastName": "Pilot",
        "groups": ["/staff"],
        "expect_admin": True,
    },
    {
        "env_user": "PILOT_STUDENT_USERNAME",
        "env_pass": "PILOT_STUDENT_PASSWORD",
        "env_email": "PILOT_STUDENT_EMAIL",
        "username": "student-pilot",
        "email": "student-pilot@qa.guru",
        "firstName": "Student",
        "lastName": "Pilot",
        "groups": ["/students"],
        "expect_admin": False,
    },
)


def ssl_ctx() -> ssl.SSLContext:
    if certifi is not None:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()


def load_kv(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.is_file():
        return env
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def sonar_token() -> str:
    if not SONAR_TOKEN_FILE.is_file():
        raise SystemExit(f"missing {SONAR_TOKEN_FILE}")
    return SONAR_TOKEN_FILE.read_text(encoding="utf-8").strip()


def sonar_request(
    path: str,
    *,
    method: str = "GET",
    params: dict[str, str] | None = None,
    token: str | None = None,
    cookie: str | None = None,
) -> tuple[int, Any]:
    url = SONAR_URL + path
    data = None
    if params is not None and method != "GET":
        data = urllib.parse.urlencode(params).encode()
    elif params and method == "GET":
        url += "?" + urllib.parse.urlencode(params)
    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if cookie:
        headers["Cookie"] = cookie
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
            raw = resp.read()
            if not raw:
                return resp.status, None
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed: Any = json.loads(body)
        except json.JSONDecodeError:
            parsed = body
        return exc.code, parsed


def sonar_ok(path: str, **kwargs: Any) -> Any:
    token = kwargs.pop("token", None)
    if token is None:
        token = sonar_token()
    code, body = sonar_request(path, token=token, **kwargs)
    if code >= 400:
        raise SystemExit(f"{kwargs.get('method', 'GET')} {path} -> {code} {body!r}"[:500])
    return body


def auth_env() -> dict[str, str]:
    env = load_kv(AUTH_ENV_FILE)
    if not env.get("KC_BOOTSTRAP_ADMIN_USERNAME"):
        raise SystemExit(f"missing bootstrap admin in {AUTH_ENV_FILE}")
    return env


def keycloak_token(env: dict[str, str]) -> str:
    form = urllib.parse.urlencode(
        {
            "client_id": "admin-cli",
            "grant_type": "password",
            "username": env["KC_BOOTSTRAP_ADMIN_USERNAME"],
            "password": env["KC_BOOTSTRAP_ADMIN_PASSWORD"],
        }
    ).encode()
    req = urllib.request.Request(
        f"{AUTH_URL}/realms/master/protocol/openid-connect/token",
        data=form,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
        return json.loads(resp.read())["access_token"]


def kc(method: str, path: str, token: str, body: Any = None) -> Any:
    data = None
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(f"{AUTH_URL}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"{method} {path} -> {exc.code} {exc.read()[:300]!r}") from exc


# ---------------------------------------------------------------------------
# inventory
# ---------------------------------------------------------------------------


def cmd_inventory() -> int:
    INV_DIR.mkdir(mode=0o700, exist_ok=True)
    users: list[dict[str, Any]] = []
    page = 1
    while True:
        data = sonar_ok("/api/users/search", params={"p": str(page), "ps": "100"})
        batch = data.get("users") or []
        users.extend(batch)
        total = (data.get("paging") or {}).get("total", len(users))
        if len(users) >= total or not batch:
            break
        page += 1

    groups = (sonar_ok("/api/user_groups/search", params={"ps": "100"}).get("groups") or [])
    membership: dict[str, list[str]] = {}
    for group in groups:
        name = group["name"]
        md = sonar_ok("/api/user_groups/users", params={"name": name, "ps": "100"})
        membership[name] = [u["login"] for u in md.get("users") or [] if u.get("selected")]

    tokens = sonar_ok("/api/user_tokens/search")
    token_names = [
        {"name": t.get("name"), "type": t.get("type"), "lastConnectionDate": t.get("lastConnectionDate")}
        for t in tokens.get("userTokens") or []
    ]

    mapping = []
    for user in users:
        login = user.get("login")
        if login == "admin":
            decision = "break-glass local; never create in Keycloak; CI tokens live here"
        elif user.get("externalProvider") == "saml":
            decision = "JIT then align login to Keycloak handle (SONAR-12475 suffix)"
        else:
            decision = "keep current username; SSO later under the same login, do not rename"
        mapping.append(
            {
                "sonar_login": login,
                "handle": login if login != "admin" else None,
                "local": user.get("local"),
                "tokensCount": user.get("tokensCount"),
                "decision": decision,
            }
        )

    payload = {
        "when": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "user_count": len(users),
        "users": [
            {
                "login": u.get("login"),
                "name": u.get("name"),
                "active": u.get("active"),
                "local": u.get("local"),
                "externalProvider": u.get("externalProvider"),
                "tokensCount": u.get("tokensCount"),
            }
            for u in users
        ],
        "groups": [{"name": g.get("name"), "members": g.get("membersCount"), "members_logins": membership.get(g["name"], [])} for g in groups],
        "tokens_on_admin": token_names,
        "username_map": mapping,
        "ci_plan": (
            "Both live tokens (ci-reference-app, admin-sync-qa-guru) belong to local admin. "
            "SAML does not swap that realm. No reissue this window. Never SAML-login as admin."
        ),
    }
    dest_name = os.environ.get("P2B_SNAPSHOT")
    if not dest_name:
        dest_name = "after.json" if (INV_DIR / "before.json").is_file() else "before.json"
    dest = INV_DIR / dest_name
    dest.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    dest.chmod(0o600)
    (INV_DIR / "username-map.json").write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"ok": True, "user_count": len(users), "wrote": str(dest), "logins": [u.get("login") for u in users]}, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------------------
# groups on Sonar — before anyone SAML-logs in
# ---------------------------------------------------------------------------


def _create_group(name: str, description: str) -> str:
    code, body = sonar_request(
        "/api/user_groups/create",
        method="POST",
        params={"name": name, "description": description},
        token=sonar_token(),
    )
    if code in (200, 204) and isinstance(body, dict):
        return "created"
    text = json.dumps(body) if not isinstance(body, str) else body
    if code == 400 and "already exists" in text.lower():
        return "exists"
    raise SystemExit(f"create group {name} -> {code} {text[:300]}")


def _add_global_perm(group: str, permission: str) -> None:
    code, body = sonar_request(
        "/api/permissions/add_group",
        method="POST",
        params={"groupName": group, "permission": permission},
        token=sonar_token(),
    )
    if code in (200, 204):
        return
    text = json.dumps(body) if not isinstance(body, str) else body
    if code == 400 and "already" in text.lower():
        return
    raise SystemExit(f"perm {group}/{permission} -> {code} {text[:300]}")


def _add_template_perm(group: str, permission: str) -> None:
    code, body = sonar_request(
        "/api/permissions/add_group_to_template",
        method="POST",
        params={"templateName": TEMPLATE_NAME, "groupName": group, "permission": permission},
        token=sonar_token(),
    )
    if code in (200, 204):
        return
    text = json.dumps(body) if not isinstance(body, str) else body
    if code == 400 and "already" in text.lower():
        return
    raise SystemExit(f"template {group}/{permission} -> {code} {text[:300]}")


def cmd_ensure_groups() -> int:
    actions = {
        STAFF_GROUP: _create_group(STAFF_GROUP, "Keycloak staff — school admins (P2b SAML)"),
        STUDENTS_GROUP: _create_group(STUDENTS_GROUP, "Keycloak students (P2b SAML)"),
    }
    for perm in STAFF_GLOBAL_PERMS:
        _add_global_perm(STAFF_GROUP, perm)
    for perm in STAFF_TEMPLATE_PERMS:
        _add_template_perm(STAFF_GROUP, perm)
    for perm in STUDENTS_TEMPLATE_PERMS:
        _add_template_perm(STUDENTS_GROUP, perm)
    perms = sonar_ok("/api/permissions/groups", params={"ps": "100"})
    by_name = {g["name"]: g.get("permissions") for g in perms.get("groups") or []}
    print(
        json.dumps(
            {
                "ok": True,
                "groups": actions,
                "staff_global": by_name.get(STAFF_GROUP),
                "students_global": by_name.get(STUDENTS_GROUP),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


# ---------------------------------------------------------------------------
# Keycloak people — not seed-stand-users.py (that file is stand-only)
# ---------------------------------------------------------------------------


def ensure_pilot_env() -> dict[str, str]:
    env = load_kv(PILOT_ENV_FILE)
    changed = False
    lines = [
        "# P2b pilot people on prod Keycloak. Mode 600. Not git, not chat.",
        f"PILOT_STAFF_USERNAME={env.get('PILOT_STAFF_USERNAME', 'staff-pilot')}",
        f"PILOT_STAFF_EMAIL={env.get('PILOT_STAFF_EMAIL', 'staff-pilot@qa.guru')}",
        f"PILOT_STAFF_PASSWORD={env.get('PILOT_STAFF_PASSWORD') or secrets.token_urlsafe(18)}",
        f"PILOT_STUDENT_USERNAME={env.get('PILOT_STUDENT_USERNAME', 'student-pilot')}",
        f"PILOT_STUDENT_EMAIL={env.get('PILOT_STUDENT_EMAIL', 'student-pilot@qa.guru')}",
        f"PILOT_STUDENT_PASSWORD={env.get('PILOT_STUDENT_PASSWORD') or secrets.token_urlsafe(18)}",
    ]
    if not PILOT_ENV_FILE.is_file() or not env.get("PILOT_STAFF_PASSWORD") or not env.get("PILOT_STUDENT_PASSWORD"):
        changed = True
        PILOT_ENV_FILE.parent.mkdir(mode=0o700, exist_ok=True)
        PILOT_ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
        PILOT_ENV_FILE.chmod(0o600)
    return load_kv(PILOT_ENV_FILE) | {"_created": "true" if changed else "false"}


def _group_ids(token: str) -> dict[str, str]:
    groups = kc("GET", f"/admin/realms/{REALM}/groups", token) or []
    return {g["path"]: g["id"] for g in groups}


def cmd_seed_idp() -> int:
    pilot = ensure_pilot_env()
    token = keycloak_token(auth_env())
    paths = _group_ids(token)
    results = []
    for person in PILOT_PEOPLE:
        username = pilot.get(person["env_user"], person["username"])
        password = pilot[person["env_pass"]]
        email = pilot.get(person["env_email"], person["email"])
        existing = kc("GET", f"/admin/realms/{REALM}/users?username={urllib.parse.quote(username)}&exact=true", token) or []
        payload = {
            "username": username,
            "firstName": person["firstName"],
            "lastName": person["lastName"],
            "email": email,
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }
        if existing:
            user_id = existing[0]["id"]
            kc("PUT", f"/admin/realms/{REALM}/users/{user_id}", token, payload)
            action = "updated"
        else:
            kc("POST", f"/admin/realms/{REALM}/users", token, payload)
            created = kc("GET", f"/admin/realms/{REALM}/users?username={urllib.parse.quote(username)}&exact=true", token)
            user_id = created[0]["id"]
            action = "created"
        for path in person["groups"]:
            gid = paths.get(path)
            if not gid:
                raise SystemExit(f"Keycloak group {path} missing — realm import broken")
            try:
                kc("PUT", f"/admin/realms/{REALM}/users/{user_id}/groups/{gid}", token, {})
            except RuntimeError as exc:
                if "409" not in str(exc):
                    raise
        results.append({"username": username, "action": action, "groups": person["groups"]})
    print(json.dumps({"ok": True, "pilot_env": str(PILOT_ENV_FILE), "created_file": pilot.get("_created"), "users": results}, ensure_ascii=False, indent=2))
    return 0


# ---------------------------------------------------------------------------
# SAML settings on Sonar
# ---------------------------------------------------------------------------


def saml_metadata() -> tuple[str, str, str]:
    req = urllib.request.Request(f"{AUTH_URL}/realms/{REALM}/protocol/saml/descriptor")
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
        raw = resp.read()
    root = ET.fromstring(raw)
    entity_id = root.attrib["entityID"]
    login_url = None
    for sso in root.findall(".//{urn:oasis:names:tc:SAML:2.0:metadata}SingleSignOnService"):
        if sso.attrib.get("Binding", "").endswith("HTTP-POST"):
            login_url = sso.attrib.get("Location")
            break
    if not login_url:
        raise SystemExit("no HTTP-POST SingleSignOnService in IdP metadata")
    cert_el = root.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate")
    if cert_el is None or not cert_el.text:
        raise SystemExit("no X509Certificate in IdP metadata")
    cert = "".join(cert_el.text.split())
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(cert[i : i + 64] for i in range(0, len(cert), 64)) + "\n-----END CERTIFICATE-----"
    return entity_id, login_url, pem


def _set_setting(key: str, value: str) -> None:
    code, body = sonar_request(
        "/api/settings/set",
        method="POST",
        params={"key": key, "value": value},
        token=sonar_token(),
    )
    if code not in (200, 204):
        raise SystemExit(f"set {key} -> {code} {body!r}"[:400])


def cmd_configure() -> int:
    entity_id, login_url, pem = saml_metadata()
    settings = {
        "sonar.core.serverBaseURL": SONAR_URL,
        "sonar.auth.saml.applicationId": SAML_CLIENT_ID,
        "sonar.auth.saml.providerName": SAML_PROVIDER_NAME,
        "sonar.auth.saml.providerId": entity_id,
        "sonar.auth.saml.loginUrl": login_url,
        "sonar.auth.saml.user.login": SAML_LOGIN_ATTR,
        "sonar.auth.saml.user.name": SAML_NAME_ATTR,
        "sonar.auth.saml.user.email": SAML_EMAIL_ATTR,
        "sonar.auth.saml.group.name": SAML_GROUP_ATTR,
        "sonar.auth.saml.signature.enabled": "false",
        "sonar.auth.saml.certificate.secured": pem,
        "sonar.auth.saml.enabled": "true",
    }
    for key, value in settings.items():
        _set_setting(key, value)
    current = sonar_ok(
        "/api/settings/values",
        params={
            "keys": ",".join(
                [
                    "sonar.auth.saml.enabled",
                    "sonar.auth.saml.applicationId",
                    "sonar.auth.saml.providerName",
                    "sonar.auth.saml.providerId",
                    "sonar.auth.saml.loginUrl",
                    "sonar.auth.saml.user.login",
                    "sonar.auth.saml.group.name",
                    "sonar.core.serverBaseURL",
                ]
            )
        },
    )
    print(
        json.dumps(
            {
                "ok": True,
                "entity_id": entity_id,
                "login_url": login_url,
                "certificate_set": True,
                "settings": current.get("settings"),
            },
            indent=2,
        )
    )
    return 0


# ---------------------------------------------------------------------------
# local admin login (break-glass)
# ---------------------------------------------------------------------------


def local_admin_login() -> str:
    password = SONAR_ADMIN_PASSWORD_FILE.read_text(encoding="utf-8").strip()
    code, body = sonar_request(
        "/api/authentication/login",
        method="POST",
        params={"login": "admin", "password": password},
    )
    # login sets JWT cookie; urllib without cookie jar loses it. Use a one-off opener.
    if code == 200:
        return "ok-no-cookie"
    raise SystemExit(f"local admin login -> {code} {body!r}"[:300])


def local_admin_session() -> str:
    password = SONAR_ADMIN_PASSWORD_FILE.read_text(encoding="utf-8").strip()
    jar = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx()),
        urllib.request.HTTPCookieProcessor(jar),
    )
    req = urllib.request.Request(
        SONAR_URL + "/api/authentication/login",
        data=urllib.parse.urlencode({"login": "admin", "password": password}).encode(),
        method="POST",
    )
    with opener.open(req, timeout=30) as resp:
        if resp.status != 200:
            raise SystemExit(f"local admin login HTTP {resp.status}")
    jwt = next((c.value for c in jar if c.name == "JWT-SESSION"), None)
    if not jwt:
        names = [c.name for c in jar]
        raise SystemExit(f"local admin login: no JWT-SESSION cookie, got {names}")
    return jwt


def ci_token_valid() -> bool:
    path = Path.home() / ".config/sonar/ci-token"
    token = path.read_text(encoding="utf-8").strip()
    code, body = sonar_request("/api/authentication/validate", token=token)
    return code == 200 and isinstance(body, dict) and body.get("valid") is True


# ---------------------------------------------------------------------------
# SAML login without a browser (HTTP-POST binding)
# ---------------------------------------------------------------------------


class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._current = {
                "action": ad.get("action", ""),
                "method": ad.get("method", "get").lower(),
                "id": ad.get("id", ""),
                "inputs": {},
            }
            self.forms.append(self._current)
        elif tag in {"input", "button"} and self._current is not None:
            name = ad.get("name")
            if name:
                self._current["inputs"][name] = ad.get("value", "")


def parse_forms(page: str) -> list[dict[str, Any]]:
    parser = FormParser()
    parser.feed(page)
    return parser.forms


def _join(base: str, action: str) -> str:
    return urllib.parse.urljoin(base, html.unescape(action))


def saml_login(username: str, password: str) -> dict[str, Any]:
    jar = CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl_ctx()),
        urllib.request.HTTPCookieProcessor(jar),
    )
    opener.addheaders = [("User-Agent", "qa-guru-p2b-saml/1.0")]

    def fetch(url: str, data: bytes | None = None, method: str | None = None) -> tuple[str, str]:
        req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"))
        with opener.open(req, timeout=45) as resp:
            return resp.geturl(), resp.read().decode("utf-8", "replace")

    url, page = fetch(f"{SONAR_URL}/sessions/init/saml")
    for _ in range(6):
        forms = parse_forms(page)
        saml = next((f for f in forms if "SAMLResponse" in f["inputs"] or "SAMLRequest" in f["inputs"]), None)
        login = next((f for f in forms if f.get("id") == "kc-form-login" or "username" in f["inputs"]), None)
        if saml:
            action = _join(url, saml["action"])
            payload = {k: v for k, v in saml["inputs"].items()}
            url, page = fetch(action, urllib.parse.urlencode(payload).encode())
            continue
        if login and "username" in login["inputs"]:
            action = _join(url, login["action"])
            payload = dict(login["inputs"])
            payload["username"] = username
            payload["password"] = password
            payload.setdefault("credentialId", "")
            url, page = fetch(action, urllib.parse.urlencode(payload).encode())
            continue
        break

    jwt = next((c.value for c in jar if c.name == "JWT-SESSION"), None)
    if not jwt:
        snippet = re.sub(r"\s+", " ", page)[:400]
        raise RuntimeError(f"SAML login for {username} did not set JWT-SESSION (last {url}): {snippet}")

    req = urllib.request.Request(
        f"{SONAR_URL}/api/users/current",
        headers={"Cookie": f"JWT-SESSION={jwt}"},
    )
    with urllib.request.urlopen(req, timeout=30, context=ssl_ctx()) as resp:
        me = json.loads(resp.read())
    jit_login = str(me.get("login") or "")
    aligned = align_saml_login(jit_login, username)
    search = sonar_ok("/api/users/search", params={"q": aligned})
    row = next((u for u in search.get("users") or [] if u.get("login") == aligned), None)
    return {
        "login": aligned,
        "jit_login": jit_login,
        "local": False if row is None else row.get("local"),
        "externalProvider": None if row is None else row.get("externalProvider"),
        "externalIdentity": None if row is None else row.get("externalIdentity"),
        "groups": me.get("groups"),
        "name": me.get("name"),
    }


def align_saml_login(current_login: str, wanted: str) -> str:
    """Sonar JIT appends 5 random digits (SONAR-12475). Identity is externalIdentity.

    After first login, rename to the Keycloak handle so the username map stays 1:1.
    """
    if current_login == wanted:
        return current_login
    code, body = sonar_request(
        "/api/users/update_login",
        method="POST",
        params={"login": current_login, "newLogin": wanted},
        token=sonar_token(),
    )
    if code not in (200, 204):
        raise RuntimeError(f"update_login {current_login} -> {wanted}: {code} {body!r}"[:400])
    return wanted


def cmd_login_check() -> int:
    pilot = load_kv(PILOT_ENV_FILE)
    if not pilot.get("PILOT_STAFF_PASSWORD"):
        raise SystemExit(f"missing {PILOT_ENV_FILE} — run seed-idp first")
    results = []
    for person in PILOT_PEOPLE:
        username = pilot.get(person["env_user"], person["username"])
        password = pilot[person["env_pass"]]
        me = saml_login(username, password)
        groups = set(me.get("groups") or [])
        group_perms = sonar_ok("/api/permissions/groups", params={"ps": "100"})
        admin_groups = {
            g["name"]
            for g in group_perms.get("groups") or []
            if "admin" in (g.get("permissions") or [])
        }
        effective_admin = bool(groups & admin_groups)
        expect = person["expect_admin"]
        ok = (
            me.get("login") == username
            and me.get("externalIdentity") == username
            and me.get("externalProvider") == "saml"
            and effective_admin is expect
        )
        results.append(
            {
                "username": username,
                "ok": ok,
                "sonar": me,
                "effective_admin": effective_admin,
                "expect_admin": expect,
                "groups": sorted(groups),
            }
        )
        if not ok:
            print(json.dumps({"ok": False, "results": results}, ensure_ascii=False, indent=2))
            return 1
    different = results[0]["effective_admin"] != results[1]["effective_admin"]
    print(json.dumps({"ok": True, "staff_vs_students_differ": different, "results": results}, ensure_ascii=False, indent=2))
    return 0 if different else 1


# ---------------------------------------------------------------------------
# verify + break-glass
# ---------------------------------------------------------------------------


def user_count() -> int:
    data = sonar_ok("/api/users/search", params={"ps": "1"})
    return int((data.get("paging") or {}).get("total") or 0)


def cmd_verify() -> int:
    checks: list[tuple[str, bool, str]] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append((name, ok, detail))

    settings = {
        s["key"]: s.get("value")
        for s in (sonar_ok("/api/settings/values", params={"keys": "sonar.auth.saml.enabled,sonar.auth.saml.applicationId,sonar.auth.saml.group.name,sonar.core.serverBaseURL"}).get("settings") or [])
    }
    check("SAML enabled", settings.get("sonar.auth.saml.enabled") == "true", json.dumps(settings))
    check("applicationId is sonar", settings.get("sonar.auth.saml.applicationId") == SAML_CLIENT_ID, settings.get("sonar.auth.saml.applicationId", ""))
    check("group attribute set", settings.get("sonar.auth.saml.group.name") == SAML_GROUP_ATTR)
    check("serverBaseURL", settings.get("sonar.core.serverBaseURL") == SONAR_URL, settings.get("sonar.core.serverBaseURL", ""))

    groups = {g["name"] for g in (sonar_ok("/api/user_groups/search", params={"ps": "100"}).get("groups") or [])}
    check("staff group exists", STAFF_GROUP in groups)
    check("students group exists", STUDENTS_GROUP in groups)

    jwt = local_admin_session()
    check("local admin JWT", bool(jwt))
    check("CI token still valid", ci_token_valid())

    before = json.loads((INV_DIR / "before.json").read_text(encoding="utf-8")) if (INV_DIR / "before.json").is_file() else {}
    before_n = int(before.get("user_count") or 0)
    now = user_count()
    check("user count did not drop", now >= before_n, f"{before_n} -> {now}")

    width = max(len(n) for n, _, _ in checks)
    for name, ok, detail in checks:
        print(f"{'ok  ' if ok else 'FAIL'}  {name.ljust(width)}  {detail}".rstrip())
    failed = [n for n, ok, _ in checks if not ok]
    print(f"\n{len(checks) - len(failed)}/{len(checks)} checks passed")
    return 1 if failed else 0


def _docker_keycloak(action: str) -> subprocess.CompletedProcess[str]:
    # systemd unit is Type=oneshot RemainAfterExit — `systemctl start` is a no-op
    # while the unit is "active (exited)". qaguru cannot read /etc/keycloak/keycloak.env
    # (root 600), so compose up as qaguru fails. Stop/start the container as root.
    container = os.environ.get("KEYCLOAK_CONTAINER", "auth-qa-guru-keycloak-1")
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "auth-qa-guru", f"sudo docker {action} {container}"],
        check=False,
        capture_output=True,
        text=True,
    )


def cmd_break_glass() -> int:
    # Local admin must work while Keycloak is down. Always bring Keycloak back.
    local_admin_session()
    print("ok    local admin before stop")
    stop = _docker_keycloak("stop")
    if stop.returncode != 0:
        raise SystemExit(f"failed to stop Keycloak: {stop.stderr or stop.stdout}")
    result = 1
    restarted = False
    ready = False
    try:
        time.sleep(2)
        try:
            req = urllib.request.Request(f"{SONAR_URL}/sessions/init/saml")
            with urllib.request.urlopen(req, timeout=20, context=ssl_ctx()) as resp:
                saml_status = resp.status
        except urllib.error.HTTPError as exc:
            saml_status = exc.code
        except (urllib.error.URLError, TimeoutError, OSError):
            saml_status = 0
        jwt2 = local_admin_session()
        ci_ok = ci_token_valid()
        print(json.dumps({"saml_init_status": saml_status, "local_admin": bool(jwt2), "ci_token": ci_ok}, indent=2))
        if jwt2 and ci_ok:
            print("ok    local admin + CI token while Keycloak is down")
            result = 0
    finally:
        start = _docker_keycloak("start")
        restarted = start.returncode == 0
        if restarted:
            for _ in range(40):
                try:
                    req = urllib.request.Request(f"{AUTH_URL}/realms/{REALM}/protocol/saml/descriptor")
                    with urllib.request.urlopen(req, timeout=10, context=ssl_ctx()) as resp:
                        if resp.status == 200:
                            print("ok    Keycloak back")
                            ready = True
                            break
                except (urllib.error.URLError, TimeoutError, OSError, urllib.error.HTTPError):
                    time.sleep(3)
        if not restarted:
            print(
                "FAIL  Keycloak did not start back — ssh auth-qa-guru 'sudo docker start auth-qa-guru-keycloak-1'",
                file=sys.stderr,
            )
        elif not ready:
            print("FAIL  Keycloak did not become ready", file=sys.stderr)
    if not restarted or not ready:
        return 1
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "command",
        choices=("inventory", "ensure-groups", "seed-idp", "configure", "verify", "login-check", "break-glass"),
    )
    args = parser.parse_args()
    dispatch = {
        "inventory": cmd_inventory,
        "ensure-groups": cmd_ensure_groups,
        "seed-idp": cmd_seed_idp,
        "configure": cmd_configure,
        "verify": cmd_verify,
        "login-check": cmd_login_check,
        "break-glass": cmd_break_glass,
    }
    return dispatch[args.command]()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.HTTPError as exc:
        print(f"HTTP {exc.code} {exc.url} {exc.read()[:300]!r}", file=sys.stderr)
        raise
