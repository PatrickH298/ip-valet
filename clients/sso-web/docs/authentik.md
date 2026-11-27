# Signing in with authentik (OpenID Connect)

This guide connects sso-web to [authentik](https://goauthentik.io) over
OpenID Connect. People sign in with their authentik account, and their
authentik groups decide where their addresses go.

The names below are placeholders; use your own:

| | Example |
| --- | --- |
| authentik | `https://auth.example.com` |
| sso-web | `https://ip.example.com` |
| Application slug | `ip-valet` |
| Groups | `users`, `admins` |

authentik's labels move a little between releases. If a field is named
slightly differently in your version, go by what it does.

## 1. Groups in authentik

Under **Directory → Groups**, create the groups your rules will name, for
example `users` and `admins`, and add people to them.

sso-web compares group names exactly, so `Admins` and `admins` are
different groups.

## 2. The provider and application

In the admin interface, go to **Applications → Applications** and choose
**Create with provider** (on older versions, create the provider under
**Applications → Providers** first, then the application).

**Application**

- **Name:** `ip-valet`
- **Slug:** `ip-valet`. The slug is part of the issuer URL below.
- **Launch URL** (optional): `https://ip.example.com`, so the app opens from
  people's authentik library.

**Provider:** OAuth2/OpenID Provider

- **Authorization flow:** `default-provider-authorization-implicit-consent`
  signs people straight in. The explicit-consent flow asks them once.
- **Client type:** Confidential.
- **Client ID** and **Client Secret:** keep the generated values for step 3.
- **Redirect URIs:** one entry, matching mode *Strict*:
  `https://ip.example.com/auth/callback`
- **Signing Key:** choose a key, such as *authentik Self-signed
  Certificate*. **This is required.** Without one, authentik signs ID tokens
  with the client secret (HS256), and sso-web refuses them: it only accepts
  tokens it can check against authentik's published keys.
- **Encryption Key:** leave empty. sso-web cannot read encrypted ID tokens.
- **Scopes** (under advanced protocol settings): keep the default
  `openid`, `email` and `profile` mappings. authentik's `profile` mapping
  carries what sso-web reads:
  - `preferred_username`: the authentik username;
  - `groups`: the names of the user's groups.
- **Include claims in id_token:** on is simplest. Off works too, because
  sso-web then reads the claims from authentik's userinfo endpoint.
- **Subject mode** and **issuer mode:** leave the defaults. Each provider then
  has its own issuer, based on the slug.

When the provider is saved, its overview page shows the **OpenID
Configuration Issuer**, for example:

```
https://auth.example.com/application/o/ip-valet/
```

### Who may use it (optional)

On the application's **Policy / Group / User Bindings** tab, bind the groups
that should see the app, for example `users` and `admins`. Without any
binding, every authentik user may sign in to the app. sso-web still turns
away anyone its rules do not take, but bindings stop authentik from issuing
them a token at all, and keep the app out of their library.

## 3. sso-web

In the `sso-web` service of `compose.yaml`:

```yaml
      IPVALET_SSO_PUBLIC_URL: https://ip.example.com
      IPVALET_SSO_PROVIDER: oidc
      # Exactly as the provider's overview page shows it, trailing slash included.
      IPVALET_SSO_OIDC_ISSUER: https://auth.example.com/application/o/ip-valet/
      IPVALET_SSO_OIDC_CLIENT_ID: <the Client ID>
      IPVALET_SSO_OIDC_CLIENT_SECRET: <the Client Secret>
      # authentik sends groups with the profile scope; it needs no "groups" scope.
      IPVALET_SSO_OIDC_SCOPES: openid profile email

      # Members of users get 12 hours in office. Members of admins get 24 hours
      # and may enter addresses. Someone in both gets the admins rule: 24 hours,
      # manual entry, entries in group admins.
      IPVALET_SSO_RULE_USERS: group=users realm=office max_ttl=12h
      IPVALET_SSO_RULE_ADMINS: group=admins realm=office max_ttl=24h manual=yes

      # Optional: Sign out also ends the authentik session.
      IPVALET_SSO_LOGOUT_URL: https://auth.example.com/application/o/ip-valet/end-session/
```

The claims sso-web reads already match authentik's, so leave
`IPVALET_SSO_OIDC_USERNAME_CLAIM` (`preferred_username`) and
`IPVALET_SSO_OIDC_GROUPS_CLAIM` (`groups`) unset.

The client secret can come from a file instead
(`IPVALET_SSO_OIDC_CLIENT_SECRET_FILE`), like the other secrets; see
[deploy/README.md](../../../deploy/README.md#using-secrets-instead-of-environment-variables).

### sso-web must reach authentik at its public URL

sso-web calls authentik directly, for discovery, the token exchange, its
signing keys and userinfo. It must use the issuer URL people see:

- authentik builds the issuer from the address it is reached at, so an
  internal name such as `http://authentik-server:9000` would give a different
  issuer, which sso-web rejects.
- That internal issuer would also name sign-in pages that browsers cannot
  open.

So the container must resolve `auth.example.com` and reach it, usually
through your reverse proxy. When authentik runs on the same host, two ways to
do that are:

- an `extra_hosts` entry pointing the name at the host:
  `"auth.example.com:host-gateway"`;
- or putting sso-web on the reverse proxy's network, with the name as an
  alias there.

If authentik's certificate comes from a private CA, mount a CA bundle that
includes it, and point `SSL_CERT_FILE` at it.

## 4. Check, then start

```bash
docker compose run --rm sso-web check
```

`Identity provider: OK (OpenID Connect)` means sso-web found authentik and its
keys. The command also checks the API key and lists the rules. Then start it:

```bash
docker compose up -d sso-web
```

Open `https://ip.example.com` and sign in with an authentik account in one of
the groups.

## When it does not work

| What you see | Where | Fix |
| --- | --- | --- |
| *Redirect URI Error* | authentik | The redirect URI must be exactly `https://ip.example.com/auth/callback`, and `IPVALET_SSO_PUBLIC_URL` exactly `https://ip.example.com`. |
| *Sign-in unavailable*, and `cannot reach the OpenID Connect provider` | sso-web log | The container cannot reach the issuer URL; see above. `did not match the issuer URL returned by provider` means `IPVALET_SSO_OIDC_ISSUER` differs from authentik's, often by the trailing slash or the host. |
| *Sign-in failed*, and `verifying the ID token` | sso-web log | Select a **Signing Key** in the provider, and clear the **Encryption Key**. |
| *Not signed in*, and `the OpenID Connect provider refused sign-in` | sso-web log | authentik said no, often because a binding does not include the person. The log has authentik's reason. |
| *No access* | page | sso-web logs `sign-in refused: no rule takes this user or their groups`, with the groups authentik sent. Compare them with the rules; names must match exactly. |
| *No access*, and `the IdP sent no groups claim` | sso-web log | The provider's scopes lack the default `profile` mapping, or a custom mapping leaves out `groups`. |
| Registration refused | page | The API's realm rules refused it: a cap, a lifetime, a subnet or the address. The message says which; see the [README](../README.md#rules). |
