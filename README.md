# ip-valet
Simple IP registration service. 

- [Design](docs/design.md): components, trust model, rules, the worker protocol and applied state.
- [API server implementation spec](docs/api-server-spec.md)
- [OpenAPI contract](spec/openapi.yaml) for workers and clients
- [API server](api/README.md): configuration, commands and development
- [Admin dashboard](dashboard/README.md), and its [design](docs/dashboard.md)
- [UniFi worker](workers/unifi/README.md): keeps UniFi traffic matching lists in line with registered addresses
- [Deployment](deploy/README.md): a hardened Compose setup
