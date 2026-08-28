# API09: Improper Inventory Management - Prevention

## Prevention Strategy Overview

Preventing improper inventory management is a program, not a patch. It combines **knowing what you run** (inventory and discovery), **governing how it changes** (versioning, deprecation, environment separation), and **watching it continuously** (documentation as source of truth, monitoring, external scanning). The layers below are arranged so a miss at one is caught by another.

### Core Principles

- **You can't protect what you can't see**: Discovery must be active and automated.
- **Deprecated means gone**: A version is retired only when it returns errors, not data.
- **Uniform controls**: Every version and host enforces the same authN/authZ, TLS, and rate limits.
- **Documentation is the source of truth**: The spec drives the deployment.
- **Continuous, not periodic**: Inventory is wired into CI/CD.

## 1. Build and Maintain an API Inventory

A single authoritative catalog of every API — host, version, owner, data classification, auth model, lifecycle status — kept as version-controlled code.

```yaml
# api-inventory.yaml
apis:
  - name: users-api
    host: api.example.com
    versions:
      - version: v3
        status: active
        auth: oauth2 + scopes
        data_classification: PII
        owner: identity-team
        openapi: specs/users-v3.yaml
      - version: v2
        status: deprecated
        sunset_date: 2024-06-30
      - version: v1
        status: retired          # MUST return 410, verified by CI
        retired_date: 2023-01-15
```

Enrich the catalog automatically from sources that already know your traffic: the API gateway, service mesh, load balancers, DNS, and cloud inventories. Reconcile discovered endpoints against the declared inventory and flag anything unaccounted for.

## 2. Versioning and a Real Deprecation Policy

Adopt an explicit scheme and a *lifecycle* with enforced sunset dates. Announce deprecation with headers so clients migrate.

```
HTTP/1.1 200 OK
Deprecation: true
Sunset: Sat, 30 Jun 2024 23:59:59 GMT
Link: <https://api.example.com/v3/users>; rel="successor-version"
```

After the sunset date the version must return `410 Gone`, asserted by an automated test so it can never silently return.

```python
def test_retired_versions_return_410():
    for host, path in RETIRED_ENDPOINTS:
        r = requests.get(f"https://{host}{path}", timeout=5)
        assert r.status_code == 410, f"{host}{path} is still live!"
```

## 3. Environment Separation

Non-production must never be reachable with production data over the public internet.

- **Network**: Put dev/staging/QA behind a VPN or IP allowlist — never a public IP + public DNS.
- **Data**: Seed non-prod with synthetic or irreversibly masked data.
- **Config**: Disable debug modes, verbose errors, and diagnostic endpoints outside development.

```nginx
map $host $is_nonprod {
    default 0;
    "~*^(dev|staging|qa|uat)-" 1;
}
server {
    if ($is_nonprod) { allow 10.20.0.0/16; deny all; }
}
```

## 4. Documentation (OpenAPI) as the Source of Truth

Make a machine-readable spec the authoritative contract, validate it in CI, and diff it on every change so an undocumented endpoint cannot ship unnoticed.

```bash
spectral lint openapi.yaml                 # lint the spec
schemathesis run openapi.yaml --checks all # test impl against the spec
oasdiff breaking committed-openapi.yaml generated-openapi.yaml \
    || (echo "Undocumented endpoint or breaking change detected"; exit 1)
```

> **Do not serve internal specs publicly.** Interactive docs, `openapi.json`, and GraphQL introspection should be disabled or authenticated in production.

## 5. Disable Framework Diagnostic Endpoints in Production

```properties
# Spring Boot: expose nothing by default, secure what you keep
management.endpoints.web.exposure.include=health
management.endpoints.web.exposure.exclude=env,heapdump,mappings,beans
management.endpoint.health.show-details=never
```

```python
# FastAPI: no interactive docs or introspection in prod
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
```

## 6. External-Facing Asset Discovery

Enumerate your surface before attackers do; reconcile against the inventory.

```bash
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sort -u > discovered_hosts.txt
httpx -l discovered_hosts.txt -status-code -title -tech-detect > live_hosts.txt
comm -23 <(sort live_hosts.txt) <(sort inventory_hosts.txt) > UNKNOWN_ASSETS.txt
[ -s UNKNOWN_ASSETS.txt ] && notify-security "Unmanaged assets found"
```

Complement scanning with **DNS hygiene**: remove records for retired hosts and watch for dangling records (subdomain-takeover risk).

## 7. Enforce Control Parity Across Versions and Hosts

Centralize security so a new control applies everywhere. An API gateway is the natural enforcement point — if *all* traffic routes through it.

```yaml
policies:
  - match: "/api/**"          # all paths, all versions
    require_auth: oauth2
    require_tls: "1.2+"
    rate_limit: 100/min
    deny_if_unlisted: true    # reject routes not in the registered inventory
```

`deny_if_unlisted` makes a shadow endpoint fail closed instead of silently serving traffic.

### TLS and Access Parity

Old versions and stale hosts often run outdated TLS or accept credentials the current surface has rotated. Enforce one TLS baseline and one credential lifecycle across every host.

## 8. Monitoring and Detection

Every endpoint in the inventory must also be in your telemetry. Alert on inventory-failure signals.

- Traffic to deprecated/retired versions
- Requests to unregistered routes (clustered 404s = fuzzing; unexpected 200s = shadow)
- Access to diagnostic paths (`/actuator`, `/swagger`, `/_debug`, `/metrics`) from outside trusted ranges
- New hosts appearing in CT logs that are not in the inventory

```python
def monitor_inventory_signals(request):
    alerts = []
    if request.path.startswith(("/api/v1", "/api/v2/legacy")):
        alerts.append(f"Traffic to deprecated endpoint: {request.path}")
    if request.path not in REGISTERED_ROUTES:
        alerts.append(f"Request to unregistered route: {request.path}")
    if any(p in request.path for p in ("/actuator", "/_debug", "/swagger")) and not is_internal(request.remote_addr):
        alerts.append(f"External access to diagnostic path: {request.path}")
    if alerts:
        send_security_alert(alerts)
```

## 9. Govern Third-Party Data Flows

Extend the inventory to integrations: for each partner/vendor connection record what data is shared, in which direction, under what auth, and who owns it. Review on the same cadence as your own endpoints, and include them in breach-impact analysis.

## Prevention Checklist

- [ ] A single, version-controlled inventory of every API host and version exists
- [ ] Discovered assets are reconciled against the inventory automatically
- [ ] Every version has a documented status and enforced sunset date
- [ ] Retired versions return `410`, asserted by an automated test
- [ ] Non-prod is off the public internet and uses masked data
- [ ] OpenAPI spec is validated in CI and not served publicly
- [ ] Framework diagnostic endpoints are disabled/authenticated in prod
- [ ] External discovery runs on a schedule
- [ ] The gateway enforces uniform controls and rejects unlisted routes
- [ ] Monitoring alerts on deprecated, unregistered, and diagnostic access
- [ ] Third-party data flows are inventoried and reviewed

## Key Takeaways

1. **Inventory-as-code** — a reviewed, machine-readable catalog is the foundation.
2. **Deprecation needs teeth** — enforce sunset with `410` and CI assertions.
3. **Separate environments hard** — non-prod off the internet, data masked.
4. **Spec drives deployment** — detect drift in CI, don't publish the spec.
5. **Discover before attackers do** — automate external scanning.
6. **Enforce parity centrally** — one gateway policy; fail closed on unlisted routes.
7. **Monitor the whole inventory** — every known endpoint feeds telemetry.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure implementations across frameworks
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Hands-On Lab](lab/api09-inventory-lab/)**: Practice discovering and retiring unmanaged endpoints
