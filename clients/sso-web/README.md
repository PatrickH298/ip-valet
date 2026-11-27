# ip-valet SSO web client

A website where people sign in with your identity provider (OpenID Connect
or SAML 2.0) and register the address they are connecting from. Their IdP
user name and groups decide which realms the address goes to and for how
long. It is an ip-valet *client*: it calls the API with one client key, and
the realms' rules, workers and audit log apply as for any other client.

Once signed in, a person sees:

- **Register this device**: their detected IPv4 and IPv6 addresses, a subnet
  for each (by default /32 and /64), and one button that registers them in
  every realm their rules allow.
- **Enter an address** (only if a rule allows it): any address or subnet,
  kept for a time they choose, within the limits.
- **Registered addresses**: what they have registered, where, its state and
  when it expires, with a Revoke button for each address.

Someone the IdP signs in but no rule takes gets a "No access" page and no
session.

The [design notes](../../docs/sso-web.md) explain the choices.

## Setting it up

1. **In ip-valet** (the admin dashboard): create the realms, a worker
   subscribed to them (an entry no worker applies is refused), and a client
   bound to every realm the rules name. Create a key on the client's page.
2. **At the IdP**: register this site (below), with its groups in the
   token or assertion.
3. **Configure** the `sso-web` service in the
   [Compose example](../../deploy/compose.example.yaml), which lists and
   explains every variable. The required ones are `IPVALET_SSO_PUBLIC_URL`,
   `IPVALET_SSO_API_URL`, `IPVALET_SSO_API_KEY`, `IPVALET_SSO_PROVIDER` with its
   settings, and at least one rule.
4. **Check** it before starting. This validates the configuration, lists the
   rules, contacts the IdP and checks that the key may use every realm:

   ```bash
   docker compose run --rm sso-web check
   ```

Put it behind your reverse proxy with TLS, and set
`IPVALET_SSO_TRUSTED_PROXIES` to the proxy's address (see below).

## Rules

One environment variable per rule, `IPVALET_SSO_RULE_<NAME>`, holding
space-separated `key=value` pairs:

| Key | Default | Meaning |
| --- | --- | --- |
| `realm` | (required) | The realm addresses go to |
| `user` | `*` | An IdP user name, or `*` |
| `group` | `*` | An IdP group, or `*` |
| `as` | the group | The group the entries carry in ip-valet; required when `group` is `*` |
| `max_ttl` | (required) | The longest a person may keep an address: `90m`, `12h`, `30d` or `unlimited` |
| `ttl` | `max_ttl` | How long one click keeps it |
| `manual` | `no` | `yes` lets people type in addresses as well |

A person gets every rule that takes them. Someone in groups `a` and `b`, with
one rule sending `a` to realm A and another sending `b` to realm B, has each
address registered in both realms.

Several rules that send someone to the **same realm** merge into one, and the
most permissive wins:

- **Lifetimes:** the longest `max_ttl` and the longest `ttl`.
- **Manual entry:** allowed if any of them allows it.
- **Group:** the entry carries the group of the most permissive rule. That is
  the one with the longest `max_ttl`; on a tie, one that allows manual entry,
  then the longest `ttl`, then the first by name.

For example, patrick is in both `users` and `admins`:

```bash
IPVALET_SSO_RULE_USERS='group=users realm=office max_ttl=12h'
IPVALET_SSO_RULE_ADMINS='group=admins realm=office max_ttl=24h manual=yes'
```

He gets 24 hours and manual entry in office, and his address is registered
there once, in group `admins`. Someone in `users` alone gets 12 hours and no
manual entry.

```bash
IPVALET_SSO_RULE_STAFF='group=staff realm=office max_ttl=12h'
IPVALET_SSO_RULE_VPN='group="VPN users" realm=vpn max_ttl=30d ttl=7d manual=yes'
IPVALET_SSO_RULE_ME='user=patrick realm=home as=owner max_ttl=unlimited ttl=30d manual=yes'
```

Every entry also passes the realm's own rules in ip-valet: IP rules, prefix
rules, TTL rules and caps. sso-web reports each refusal to the person in
plain words:

- **Cap:** "You already have the most addresses vpn allows (2). Revoke one below
  to register another."
- **Prefix:** "office accepts IPv4 subnets no wider than /32."
- **IP rules:** the realm does not accept this address.
- **Routing:** nothing applies that address family in the realm yet.
- **TTL, one click:** the person chose no lifetime, so a realm that allows less
  than the rule's `ttl` is asked again for its longest lifetime, and the result
  says so.
- **TTL, manual entry:** the person is told the limit.

Each realm is submitted separately, so a limit in one never blocks another.

## Identity providers

Step-by-step guide: [authentik over OpenID Connect](docs/authentik.md).

**OpenID Connect.** Register a confidential client with the redirect URI
`<IPVALET_SSO_PUBLIC_URL>/auth/callback`, and set:

- `IPVALET_SSO_OIDC_ISSUER`
- `IPVALET_SSO_OIDC_CLIENT_ID`
- `IPVALET_SSO_OIDC_CLIENT_SECRET` (leave it empty for a public client)

The flow is the authorization code flow with PKCE, state and nonce. The user
name and groups come from the ID token, or from userinfo when the ID token
lacks them:

- **User name:** `IPVALET_SSO_OIDC_USERNAME_CLAIM`, default `preferred_username`.
- **Groups:** `IPVALET_SSO_OIDC_GROUPS_CLAIM`, default `groups`. A dotted name
  reaches into nested claims, such as `realm_access.roles` for Keycloak realm
  roles.

The default scopes are `openid profile email groups`. Remove `groups` from
`IPVALET_SSO_OIDC_SCOPES` if your IdP rejects it.

**SAML 2.0.** Give the IdP this site's metadata at
`<IPVALET_SSO_PUBLIC_URL>/saml/metadata`; responses are posted to `/saml/acs`.
Set:

- the IdP's metadata, by URL (`IPVALET_SSO_SAML_IDP_METADATA_URL`) or as a
  file (`IPVALET_SSO_SAML_IDP_METADATA_FILE`);
- the attribute that holds the groups (`IPVALET_SSO_SAML_GROUPS_ATTRIBUTE`,
  matched against its Name or FriendlyName).

The user name is the subject's NameID unless
`IPVALET_SSO_SAML_USERNAME_ATTRIBUTE` names an attribute. An optional key pair
(`IPVALET_SSO_SAML_SP_KEY_FILE`, `IPVALET_SSO_SAML_SP_CERT_FILE`) signs requests
and lets the IdP encrypt assertions.

Only groups that some rule names are kept in the session. A user name or
group must be 1 to 256 characters without control characters, as ip-valet
requires.

## Address detection

The page sees the address of its own connection, which is one family:
whichever the browser chose. To find the other, it needs a host reachable
over that family only. Create two DNS names, one with only an A record and
one with only an AAAA record, and have your reverse proxy send both to
sso-web's detection endpoint, either:

- on the site's own port, at the path `/detect`; or
- on a port of its own, `IPVALET_SSO_DETECT_LISTEN_ADDR` (for example
  `:8092`), which serves only detection, at `/` and `/detect`.

Then set `IPVALET_SSO_DETECT_V4_URL` and `IPVALET_SSO_DETECT_V6_URL` to their
public URLs. They must be https when the site is. For example, with Caddy:

```
ip.example.com {
	reverse_proxy sso-web:8091
}
v4.ip.example.com, v6.ip.example.com {
	reverse_proxy sso-web:8092
}
```

A small script on the page asks those hosts. Each answers with the address it
saw and a signed proof, tied to the person's session, which the register form
sends back. So sso-web only registers addresses it saw itself, never one the
browser claims. Without the script, or without the hosts, the page registers
the address of its own connection.

**Behind a proxy, set `IPVALET_SSO_TRUSTED_PROXIES`.** It defaults to trusting
every peer's `X-Forwarded-For`, like the API and the dashboard. For this site
that means anyone who can reach the container without going through your
proxy can register any address with one click, manual entry or not. sso-web
logs a warning at start while it is unset. Set it to your proxy's address or
subnet, or to `none` when there is no proxy. If an untrusted peer sends
`X-Forwarded-For` (your proxy, not yet listed), sso-web logs that once.

## Security notes

- **Sessions:** held in memory for 1 hour idle and 12 hours in all, by default.
  A restart signs everyone out; the next visit signs them in again through the
  IdP. Run one instance, or pin each person to one.
- **Forms:** forms from other sites are refused (Go's cross-origin protection),
  except the SAML response the IdP posts to `/saml/acs`. That response must
  carry the signed RelayState of a sign-in this browser began, and, over HTTPS,
  the matching cookie.
- **Pages:** a strict Content-Security-Policy. Scripts come from the site only,
  and the page may connect only to the two detection hosts.
- **Revoke:** removes only the signed-in person's own entries for that address,
  and only in realms their rules name.

## Container image

```bash
docker build -t ip-valet-sso-web clients/sso-web/
```

Built from `gcr.io/distroless/static-debian12:nonroot`. It runs as a non-root
user, uid and gid 65532, or as any other you give it (`docker run --user
1000:1000`, or `user:` in Compose). It needs no writable filesystem and
exposes 8091 (the site) and 8092 (detection, when enabled).

## Development

```bash
cd clients/sso-web
go vet ./...
IPVALET_TEST_DATABASE_URL='postgres://postgres@localhost:5432/postgres?sslmode=disable' go test ./...
```

The end-to-end tests build the API server from `../../api` and run it against
Postgres. They sign in through a fake OpenID Connect provider (PKCE, RS256 ID
tokens, userinfo) and through crewjam/saml's identity provider, and drive the
site with a cookie-jar client. Without `IPVALET_TEST_DATABASE_URL` they are
skipped; in CI they fail instead.
