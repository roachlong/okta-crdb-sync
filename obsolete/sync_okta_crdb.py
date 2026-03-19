#!/usr/bin/env python3
import argparse, os, sys, re, json
from typing import Dict, List, Set
import requests, yaml, psycopg

def log(msg, *, verbose=False, level="info"):
    levels = dict(debug=10, info=20, warn=30, error=40)
    cur = levels["debug" if verbose else "info"]
    if levels.get(level, 20) >= cur:
        print(f"[{level.upper()}] {msg}")

def die(msg, code=1):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)

class OktaClient:
    def __init__(self, org_url: str, token: str, page_size: int = 200, verbose=False):
        self.base = org_url.rstrip("/")
        self.token = token
        self.page_size = min(max(page_size, 1), 200)
        self.verbose = verbose
        self.sess = requests.Session()
        self.sess.headers.update({"Authorization": f"SSWS {self.token}", "Accept": "application/json"})

    def _get(self, path, params=None):
        url = f"{self.base}{path}"
        r = self.sess.get(url, params=params, timeout=30)
        if r.status_code >= 300:
            raise RuntimeError(f"Okta GET {url} failed: {r.status_code} {r.text}")
        return r

    def find_group_id_by_name(self, name: str) -> str:
        params = {"search": f'profile.name sw "{name}"', "limit": self.page_size}
        r = self._get("/api/v1/groups", params=params)
        for g in r.json():
            if g.get("profile", {}).get("name") == name:
                return g["id"]
        params = {"q": name, "limit": self.page_size}
        r = self._get("/api/v1/groups", params=params)
        for g in r.json():
            if g.get("profile", {}).get("name") == name:
                return g["id"]
        raise KeyError(f"Okta group named '{name}' not found")

    def list_group_user_emails(self, group_id: str) -> List[str]:
        emails = []
        after = None
        import re as _re
        while True:
            params = {"limit": self.page_size}
            if after: params["after"] = after
            r = self._get(f"/api/v1/groups/{group_id}/users", params=params)
            items = r.json()
            for u in items:
                email = u.get("profile", {}).get("email")
                if email: emails.append(email.lower())
            link = r.headers.get("Link", "")
            m = _re.search(r'<([^>]+)>;\\s*rel="next"', link)
            if m and "after=" in m.group(1):
                after = m.group(1).split("after=")[-1]
            else:
                break
        return sorted(set(emails))

class CrdbClient:
    def __init__(self, url: str, verbose=False):
        self.url = url
        self.verbose = verbose
    def connect(self):
        return psycopg.connect(self.url, autocommit=True)
    def ensure_role_exists(self, role: str):
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(f'CREATE ROLE IF NOT EXISTS "{role}"')
    def ensure_user_exists(self, user: str):
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(f'CREATE USER IF NOT EXISTS "{user}"')
    def current_members_of_role(self, role: str) -> Set[str]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT member FROM crdb_internal.role_members WHERE role = $1", (role,))
            return {r[0] for r in cur.fetchall()}
    def grant_role_to_member(self, role: str, member: str):
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(f'GRANT "{role}" TO "{member}"')
    def revoke_role_from_member(self, role: str, member: str):
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(f'REVOKE "{role}" FROM "{member}"')

def derive_sql_username(identity: str, pattern: str, replacement: str) -> str:
    m = re.match(pattern, identity)
    if not m:
        raise ValueError(f"identity '{identity}' does not match pattern '{pattern}'")
    return re.sub(pattern, replacement, identity)

def sync_one_mapping(okta: OktaClient, crdb: CrdbClient, mapping: Dict, idmap: Dict, ensure_users: bool, ensure_roles: bool, enforce_removals: bool, dry_run: bool, verbose: bool):
    okta_group = mapping["okta_group"]
    crdb_role = mapping["crdb_role"]
    gid = okta.find_group_id_by_name(okta_group)
    okta_emails = okta.list_group_user_emails(gid)
    desired_members = set()
    for email in okta_emails:
        try:
            user = derive_sql_username(email, idmap["pattern"], idmap["replacement"])
        except Exception as e:
            log(f"skipping email '{email}': {e}", verbose=verbose, level="warn")
            continue
        desired_members.add(user)
    if ensure_roles:
        if dry_run: log(f"[dry-run] would ensure role exists: {crdb_role}", verbose=verbose)
        else: crdb.ensure_role_exists(crdb_role)
    if ensure_users:
        for u in sorted(desired_members):
            if dry_run: log(f"[dry-run] would ensure user exists: {u}", verbose=verbose)
            else: crdb.ensure_user_exists(u)
    current_members = crdb.current_members_of_role(crdb_role)
    to_add = sorted(desired_members - current_members)
    to_remove = sorted(current_members - desired_members) if enforce_removals else []
    for u in to_add:
        if dry_run: log(f"[dry-run] GRANT {crdb_role} TO {u}", verbose=verbose)
        else: crdb.grant_role_to_member(crdb_role, u)
    for u in to_remove:
        if dry_run: log(f"[dry-run] REVOKE {crdb_role} FROM {u}", verbose=verbose)
        else: crdb.revoke_role_from_member(crdb_role, u)
    return {"okta_group": okta_group, "crdb_role": crdb_role, "desired_count": len(desired_members), "current_count": len(current_members), "granted": to_add, "revoked": to_remove}

def main():
    import yaml
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    cfg = yaml.safe_load(open(args.config).read())
    okta_token = os.environ.get("OKTA_API_TOKEN") or cfg["okta"].get("api_token")
    if not okta_token or okta_token.startswith("${"):
        die("OKTA_API_TOKEN not set (set env var or hardcode in config for testing)")
    okta = OktaClient(cfg["okta"]["org_url"], okta_token, page_size=cfg["okta"].get("page_size", 200), verbose=args.verbose)
    crdb = CrdbClient(cfg["crdb"]["url"], verbose=args.verbose)
    idmap = cfg.get("identity_map", {"pattern": "^(.*)$", "replacement": "\\1"})
    ensure_users = bool(cfg["crdb"].get("ensure_sql_users", True))
    ensure_roles = bool(cfg["crdb"].get("ensure_roles", True))
    enforce_removals = bool(cfg["crdb"].get("enforce_removals", False))
    results = []
    for m in cfg["mappings"]:
        results.append(sync_one_mapping(okta, crdb, m, idmap, ensure_users, ensure_roles, enforce_removals, args.dry_run, args.verbose))
    print(json.dumps({"results": results}, indent=2))

if __name__ == "__main__":
    main()
