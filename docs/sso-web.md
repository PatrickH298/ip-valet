# sso-web: design

sso-web is the first ip-valet client: a website where people sign in with an
external identity provider and register the addresses they connect from. This
note records how it works and why. The [README](../clients/sso-web/README.md)
covers setting it up.

## Shape

```
browser ──HTTPS──> reverse proxy ──> sso-web (:8091) ──client key──> API (:8080)
   │                                  ▲    │
   │  v4-only / v6-only names ────────┘    └──> IdP (OpenID Connect discovery, or SAML metadata)
   └──> IdP (sign-in)
```

- **A separate Go service** with one client key, bound to the realms its
  rules name. Like any client, it can act only in those realms, and the
  realms' rules bound what it registers.
- **No database.** Sessions live in memory, and everything else is read
  from the API on each page. A restart signs people out; with SSO the next
  visit signs them straight back in.
- **Server-rendered HTML**, with one small script for address detection.
  Without the script, the page still works and registers the connection's
  own address.

## Who may do what

The IdP says who someone is: a user name and groups. Rules
(`IPVALET_SSO_RULE_<NAME>`) turn that into **grants**, each a realm and API
group with lifetimes and a manual-entry flag:

- A rule takes people by user (a name or `*`) and group (a name or `*`). Its
  entries carry the rule's group, or `as=` when it names one. A rule that
  matches any group, or a user alone, must say which group its entries carry,
  so a realm's API groups stay a small, predictable set.
- A person gets every rule that takes them, merged per realm and API group:
  the longest lifetimes win, and manual entry is allowed if any rule allows it.
- **No grant, no session.** Someone the IdP signs in but no rule takes is
  shown "No access", and the attempt is logged with their groups.
- Only groups some rule names are kept, so a person in hundreds of IdP groups
  does not carry them all.

Rules live in the environment, like the UniFi worker's, so they are reviewed
and deployed with the rest of the configuration.

## Registering

One click registers each detected address in every grant, for the grant's
`ttl`. Manual entry registers one typed address or subnet in the grants that
allow it, for a lifetime the person chooses, capped by each grant's
`max_ttl`.

- **One submission per realm and group.** A submission is all or nothing, so
  sending each grant on its own keeps a cap in one realm from blocking the
  others.
- **Every refusal becomes a sentence.** The API's 422 names the failed check
  and its limit, and sso-web says what to do about it: revoke an address
  (`cap_exceeded`), choose a narrower subnet (`prefix_too_broad`), choose a
  shorter time (`ttl_exceeded`), or that the realm does not accept the address
  (`ip_denied`) or the family (`no_subscriber`). Problems of configuration
  (`realm_not_allowed`, a refused key) tell the person to contact the
  administrator, and are logged as errors.
- **One click adapts to TTL limits.** When a realm's own TTL rule allows less
  than the grant's `ttl`, sso-web asks again with the realm's limit and says so.
  A manual lifetime is the person's choice, so there it reports the limit
  instead.
- **Site limits come first.** The widest subnet per family
  (`IPVALET_SSO_MAX_SUBNET_V4`, `_V6`) and `max_ttl` are checked before
  anything is sent.
- **Revoking** deletes the person's own entries for one address, in the realms
  their grants name. The site looks the entries up by user and prefix; it never
  takes entry ids from the form.

## Detecting addresses

The page's own connection reveals one address, of whichever family the
browser chose. The other needs a host reachable over that family only, so
`IPVALET_SSO_DETECT_V4_URL` and `IPVALET_SSO_DETECT_V6_URL` name two such
hosts. They are proxied to this program's `/detect`, on its main port or on a
port of its own (`IPVALET_SSO_DETECT_LISTEN_ADDR`).

1. The page carries a **detection token**: the session's tag (an HMAC of its
   id) with an expiry, sealed.
2. The script fetches each detection host with the token. The host checks the
   token and answers with the address it saw, its family, and a **proof**: the
   address and the session's tag, sealed, valid for 30 minutes. CORS allows
   only the site's own origin.
3. The register form posts the proofs back. sso-web opens each, keeps those
   tied to this session, and registers those addresses together with the one
   the post itself came from.

So nothing the browser claims is registered without manual entry. A stolen
token only yields proofs for the thief's own address, tied to someone else's
session, which the thief cannot post to. The sealing key is random per
process, like the sessions.

**Trusted proxies.** Behind a reverse proxy the address comes from
`X-Forwarded-For`. The setting defaults to trusting every peer, as the API and
the dashboard do (a deployer's choice). Here that default lets anyone who
reaches the container directly register any address with one click. So the
Compose example warns beside the setting, sso-web logs a warning at start
while it is unset, and logs once when an untrusted peer sends the header.

## Sign-in

- **OpenID Connect:** the authorization code flow with PKCE (S256), state and
  nonce, using `coreos/go-oidc`. The state, nonce and verifier travel in a
  sealed, HttpOnly, SameSite=Lax cookie for ten minutes. The ID token is
  verified, and claims missing from it are read from userinfo.
- **SAML 2.0:** an SP-initiated web browser SSO, using `crewjam/saml`, with
  the HTTP-Redirect binding (or HTTP-POST when that is all the IdP offers)
  and responses posted to `/saml/acs`.
  - RelayState carries the request id, a nonce and where to return, sealed.
  - The same nonce is in a SameSite=None cookie, so over HTTPS the response
    must come back to the browser that asked.
  - Only responses to that request id are accepted; IdP-initiated sign-in is
    off.
  - An optional key pair signs requests and lets the IdP encrypt assertions.
- **The IdP is contacted lazily.** If discovery or metadata fails at start,
  that is a warning, and each sign-in tries again.

## Hardening

- **Cross-site forms:** refused by Go's `CrossOriginProtection`, except the
  SAML response endpoint, which checks the sealed RelayState and cookie
  instead.
- **Cookies:**
  - The session cookie is HttpOnly and SameSite=Lax. It takes the `__Host-`
    prefix when Secure, which `IPVALET_SSO_SECURE_COOKIES=auto` sets on HTTPS
    requests.
  - A new session id is made at every sign-in.
  - `next` targets are restricted to paths on the site.
- **Content-Security-Policy:** `default-src 'none'`; styles and scripts from
  the site only; `connect-src` only the detection hosts; `form-action` the
  site, plus the logout URL's origin when one is set.
- **Container:** distroless, non-root, no writable filesystem, any uid:gid.
