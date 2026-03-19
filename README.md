# Okta → CockroachDB Role Sync

This repository demonstrates how to setup a local cockroach cluster with an IDP and enable SSO for auto-provisioning, keeping CockroachDB SQL role memberships aligned with **Okta groups**.

## CockroachDB Setup
We'll start by configuring a local secure database database cluster that will provide the backend for testing single sign-on.  We can run cockroach as a single-node for simple use cases.

**<ins>CERTS</ins>**
1) Create a directory to hold our self-signed certificate ```mkdir -p certs my-safe-directory```
1) Then run the cockroach commands to generate the certs.
```
cockroach cert create-ca --certs-dir=certs --ca-key=my-safe-directory/ca.key
cockroach cert create-node localhost us-east us-central us-west 127.0.0.1 $(hostname -f) --certs-dir=certs --ca-key=my-safe-directory/ca.key
cockroach cert create-client root --certs-dir=certs --ca-key=my-safe-directory/ca.key
chmod 600 ./certs/node.key
chmod 600 ./certs/client.root.key
```

Copy the client certs into the default location for postgres on Mac
```
cp certs/client.root.crt ~/.postgresql/root.crt
cp certs/client.root.key ~/.postgresql/postgresql.key
```
Or on Windows
```
cp certs\client.root.crt $env:APPDATA\.postgresql\root.crt
cp certs\client.root.key $env:APPDATA\.postgresql\postgresql.key
```

**<ins>CLUSTER</ins>**

Then check your cockroach version and start your single node instance with the new certs.
```
cockroach --version
cockroach start-single-node --certs-dir=./certs --store=./data --host=localhost --background
```

<br/>**<ins>USERS</ins>**

And create a new admin user for your cluster.  **Note**: with Windows PowerShell use two pairs of double quotes around me, i.e. ``` ""me"" ```
```
cockroach sql --certs-dir ./certs --url "postgresql://localhost:26257/defaultdb?sslmode=verify-full" -e """
CREATE ROLE "me" WITH LOGIN PASSWORD 'secret';
GRANT admin TO me;
"""
```
Now you can log into the cockroachdb console for your secure cluster using the credentials you provided above at https://localhost:8080/

## Okta Setup
Next go to https://developer.okta.com/signup/ to setup a free dev tenant by signing up for the "Access the Okta Integrator Free Plan" and verify your account.

Once done you should have an admin console that you can log into, i.e. https://integrator-XXXXXXX-admin.okta.com/admin/home.  Follow the steps below to setup your tenant.

### 1) Create Your Test User

Go to:
- Directory → People → Add Person

Create:
- **Name**: John Doe
- **Email**: your real email
- **Username**: same email

This is your SSO test identity

### 2) Create and Assign Groups

Go to:
- Directory → Groups → Add Group

Create:
- crdb_admin
- crdb_dev

Click on the crdb_admin group → Assign People to add your John Doe test user account.

### 3) Create OIDC App

Go to:
- Applications → Applications → Create App Integration

Choose:
- OIDC - OpenID Connect
- Web Application

Configure it:
- **App integration name**: Local CockroachDB Cluster
- **Sign-in redirect URI**: https://localhost:8080/oidc/v1/callback
- **Sign-out redirect URI**: https://localhost:8080
- **Assignments Controlled access**: Skip group assignment for now

And capture:
- Client ID
- Client Secret

And go to Security → API → Authorization Servers for
- Okta Domain (issuer URL base)

### 4) Add Groups to Token

Go to:
- Applications → Your App → Sign On → Token Claims → Show legacy configuration → Edit

Configure:
- **Groups claim type**: Filter
- **Groups claim filter**: groups
- **Starts with**: crdb

### 5) Put Groups IN the JWT

Go to:
- Security → API → Authorization Servers → default → Claims → Add / verify claim:

Configure:
- **Name**: groups
- **Include in**: ID Token
- **Value type**: Groups
- **Filter**: Starts with "crdb"

### 6) Add Scopes to Auth Service

Go to:
- Security → API → Authorization Servers → default → Scopes → Add Scope

Configure:
- **Name**: groups
- **Display phrase**: groups
- **Description**: groups

### 7) Assign App to User

Go to:
- Applications → Your App → Assignments

And assign your test user.

### 8) Authorization Server Policy

Go to:
- Security → API → Authorization Servers → default → Access Policies → Add Policy

Configure:
- **Name**: Allow CRDB
- **Description**: policy to allow access to assigned aps

Then Add Rule:
- **Grant type**: Authorization Code
- **User**: Any
- **Scopes**: Any (or include openid, email, groups)
- **Everything Else**: Leave Defaults

## Configure CRDB with OIDC
Now we can follow the documentation at https://www.cockroachlabs.com/docs/v25.4/sso-sql to configure auto-provisioning of SQL users.

Start by enablinging JWT authentication / authorization.
```
cockroach sql --certs-dir ./certs --url "postgresql://localhost:26257/defaultdb?sslmode=verify-full" -e """
SET CLUSTER SETTING server.jwt_authentication.enabled = true;
SET CLUSTER SETTING server.jwt_authentication.authorization.enabled = true;
SET CLUSTER SETTING security.provisioning.jwt.enabled = true;
"""
```

And configure JWKS (Okta public keys)
```
export OKTA_DOMAIN=https://integrator-XXXXXXX.okta.com/oauth2/default
export OKTA_KEYS=$(curl -k ${OKTA_DOMAIN}/v1/keys)
cockroach sql --certs-dir ./certs --url "postgresql://localhost:26257/defaultdb?sslmode=verify-full" -e """
SET CLUSTER SETTING server.jwt_authentication.jwks = '${OKTA_KEYS}';
"""
```

And issuer, client ID, claim mapping, roles, etc.
```
export CLIENT_ID=secret
cockroach sql --certs-dir ./certs --url "postgresql://localhost:26257/defaultdb?sslmode=verify-full" -e """
SET CLUSTER SETTING server.jwt_authentication.issuers.configuration = '${OKTA_DOMAIN}';
SET CLUSTER SETTING server.jwt_authentication.audience = '${CLIENT_ID}';
SET CLUSTER SETTING server.jwt_authentication.claim = 'email';
SET CLUSTER SETTING server.identity_map.configuration = '${OKTA_DOMAIN} /^(.*)@.*$/ \1';
SET CLUSTER SETTING server.jwt_authentication.group_claim = 'groups';
CREATE ROLE "crdb_admin";
GRANT admin TO crdb_admin;
CREATE ROLE "crdb_dev";
GRANT CONNECT ON DATABASE defaultdb TO crdb_dev;
GRANT USAGE, CREATE ON SCHEMA public TO crdb_dev;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO crdb_dev;
"""
```

## Test Token Based Access
First we need to get a JWT from Okta using the browser using the authorization code grant type.  Navigate to https://integrator-XXXXXXX.okta.com/oauth2/default/v1/authorize?client_id=<CLIENT_ID>&response_type=code&scope=openid%20email%20groups&redirect_uri=https://localhost:8080/oidc/v1/callback&state=abc&nonce=xyz

After authenticating you will be redirected to:
https://localhost:8080/oidc/v1/callback?code=XXXXX&state=abc

Copy the code and exchange it for a token
```
export COPIED_CODE=secret
export CLIENT_SECRET=secret
export USER_TOKEN=$(curl -k -X POST ${OKTA_DOMAIN}/v1/token \
  -d "grant_type=authorization_code" \
  -d "code=${COPIED_CODE}" \
  -d "redirect_uri=https://localhost:8080/oidc/v1/callback" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" | jq -r '.id_token')
```

Now we should be able to connect using our JWT
```
export USER_PRINCIPAL=username
cockroach sql \
  --certs-dir=./certs \
  --url "postgresql://${USER_PRINCIPAL}:${USER_TOKEN}@localhost:26257/defaultdb?sslmode=verify-full&options=--crdb:jwt_auth_enabled=true"
> SHOW USERS;
> SELECT current_user;
> SHOW GRANTS FOR "username";
```

Now let's change the permisisons for our test user:
- Go back to Okta and navigate to Directory → Groups
- Move our test user from crdb_admin to crdb_dev
- Follow the steps above to get a new code and user token
- Then reconnect to cockroach sql and you should have less permissions

## Obsolete
Thanks to CockroachDB's new server.jwt_authentication.authorization.enabled and security.provisioning.jwt.enabled features, as of 25.4.6, we no longer have to run a sync and can throw this python script in the trash where it belongs...
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export OKTA_API_TOKEN=xxxxxx
python sync_okta_crdb.py --config config.yaml --dry-run --verbose
python sync_okta_crdb.py --config config.yaml --verbose
```
