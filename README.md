# Okta → CockroachDB Role Sync

Keep CockroachDB SQL role memberships aligned with **Okta groups**.

## Local run
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export OKTA_API_TOKEN=xxxxxx
python sync_okta_crdb.py --config config.yaml --dry-run --verbose
python sync_okta_crdb.py --config config.yaml --verbose
```
