# Software Supply Chain Failures - Code Examples

Each pair below shows a **vulnerable** configuration and the **secure** version for the same ecosystem. The focus is the supply chain: how dependencies are declared, resolved, verified, built, and loaded—not application logic.

## On This Page
- [Node / npm](#node--npm)
- [Python / pip](#python--pip)
- [CI/CD (GitHub Actions)](#cicd-github-actions)
- [Java / Maven](#java--maven)
- [Container Base Image](#container-base-image)
- [HTML Subresource Integrity](#html-subresource-integrity)

## Node / npm

### Vulnerable
```json
// package.json -- floating ranges auto-adopt new (possibly hijacked) releases
{
  "name": "shop-web",
  "dependencies": {
    "express": "^4.0.0",        // any 4.x, chosen at install time
    "left-utils": "*",          // literally any version
    "@acme/auth-client": "^2.0.0"  // internal name, no registry pinning
  }
}
```
```
# Install is non-deterministic and runs arbitrary lifecycle scripts.
# A dependency-confusion package @acme/auth-client@99.0.0 on the PUBLIC
# registry would be preferred over the internal 2.x.
$ npm install
```

### Secure
```json
// package.json -- exact versions; internal scope pinned to a private registry
{
  "name": "shop-web",
  "dependencies": {
    "express": "4.19.2",
    "left-utils": "1.0.0",
    "@acme/auth-client": "2.4.1"
  }
}
```
```
# .npmrc -- @acme ALWAYS resolves from the private registry (confusion defeated)
@acme:registry=https://npm.internal.acme.com/
//npm.internal.acme.com/:_authToken=${NPM_TOKEN}
save-exact=true
```
```
# Deterministic install straight from the committed lockfile (+ integrity
# hashes), with install scripts disabled for untrusted trees:
$ npm ci --ignore-scripts
# Publish with build provenance so consumers can verify the source:
$ npm publish --provenance --access restricted
```

## Python / pip

### Vulnerable
```
# requirements.txt -- unpinned; no integrity; typo installs a squatter
flask
requsets            # typo of "requests" -> could be a malicious package
python-dateutils    # look-alike of python-dateutil
```
```
$ pip install -r requirements.txt   # newest of each, whatever it is today
# setup.py of any dependency runs arbitrary code during install.
```

### Secure
```
# requirements.txt -- exact versions AND content hashes
flask==3.0.0 \
    --hash=sha256:cfadcbe0f6aa1bced4d1a8a2c65066d1f9f22a7a2d3c6b6d0f2c6f4e1b2c3d4e
requests==2.31.0 \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
python-dateutil==2.9.0.post0 \
    --hash=sha256:37dd54208da7e1cd875388217d5e00ebd4179249f90fb72437e91a35459a0ad3
```
```
# Refuse to install anything whose hash is not listed; pin the index source:
$ pip install --require-hashes \
      --index-url https://pypi.internal.acme.com/simple \
      -r requirements.txt
$ pip-audit -r requirements.txt      # scan for known vulnerabilities
```

## CI/CD (GitHub Actions)

### Vulnerable
```yaml
name: build
on: [push]
# No permissions block -> workflow gets a broad, read-write token by default
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4          # mutable tag -- can move
      - uses: some-org/deploy-action@main  # mutable branch -- fully mutable
      - run: |
          npm install                      # runs install hooks
          echo "Token is $NPM_TOKEN"       # secret leaked into public logs
          aws s3 sync ./dist s3://prod     # long-lived static AWS creds in env
```

### Secure
```yaml
name: build
on: [push]
permissions:
  contents: read        # least privilege by default
  id-token: write       # only to mint a short-lived OIDC token for AWS
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      # Third-party actions pinned by immutable commit SHA (comment = version)
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11   # v4.1.1
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e0343502  # v4.0.2
        with:
          role-to-assume: arn:aws:iam::111122223333:role/ci-deploy  # short-lived, scoped
          aws-region: us-east-1
      - run: npm ci --ignore-scripts       # deterministic, no install hooks
      - run: npx osv-scanner --lockfile package-lock.json   # SCA gate
      # No secret is ever echoed; masked secrets stay out of logs.
```

## Java / Maven

### Vulnerable
```xml
<dependencies>
  <!-- Version RANGE: resolves to whatever is newest at build time -->
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>[2.0,)</version>
  </dependency>
</dependencies>
<!-- Repositories over plain HTTP, checksums not enforced -->
<repositories>
  <repository><id>insecure</id><url>http://repo.example/maven</url></repository>
</repositories>
```

### Secure
```xml
<dependencies>
  <dependency>
    <groupId>com.fasterxml.jackson.core</groupId>
    <artifactId>jackson-databind</artifactId>
    <version>2.17.1</version>   <!-- exact, immutable -->
  </dependency>
</dependencies>

<build><plugins>
  <!-- Fail the build on version ranges / dependency convergence issues -->
  <plugin>
    <groupId>org.apache.maven.plugins</groupId>
    <artifactId>maven-enforcer-plugin</artifactId>
    <version>3.5.0</version>
    <executions><execution>
      <goals><goal>enforce</goal></goals>
      <configuration><rules>
        <requireReleaseDeps/>
        <banDynamicVersions/>
        <dependencyConvergence/>
      </rules></configuration>
    </execution></executions>
  </plugin>
</plugins></build>
```
```
# Build over HTTPS with strict checksum verification; scan dependencies.
$ mvn --strict-checksums verify
$ mvn org.owasp:dependency-check-maven:check   # SCA for known CVEs
```

## Container Base Image

### Vulnerable
```dockerfile
# Mutable tag: contents can change between builds; runs as root
FROM node:latest
WORKDIR /app
COPY . .
RUN npm install          # non-deterministic, runs install hooks
CMD ["node", "server.js"]
```

### Secure
```dockerfile
# Build stage pinned by DIGEST (immutable)
FROM node:20.11.1-bookworm-slim@sha256:8b1e6c...c0a2 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# Minimal, non-root runtime with no shell/package manager to abuse
FROM gcr.io/distroless/nodejs20-debian12@sha256:5f3d...9ab1
WORKDIR /app
COPY --from=build /app/dist ./dist
USER nonroot
CMD ["dist/server.js"]
```
```
# Scan and verify before the image is allowed to deploy
$ trivy image --severity HIGH,CRITICAL myapp@sha256:9c1f...ab
$ cosign verify myregistry/base@sha256:5f3d...9ab1
```

## HTML Subresource Integrity

### Vulnerable
```html
<!-- Whatever the CDN serves today runs in your page with full DOM access.
     If the CDN or third party is compromised, a skimmer is injected. -->
<script src="https://cdn.thirdparty.example/analytics.js"></script>
<link  rel="stylesheet" href="https://cdn.thirdparty.example/widget.css">
<!-- "latest" URLs are mutable by design -- no way to detect a swap -->
<script src="https://cdn.thirdparty.example/lib/latest/lib.js"></script>
```

### Secure
```html
<!-- Pin an immutable version and require a matching hash. The browser
     refuses to execute the file if its content changes. -->
<script src="https://cdn.thirdparty.example/analytics@3.2.1/analytics.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"
        referrerpolicy="no-referrer"></script>

<link rel="stylesheet"
      href="https://cdn.thirdparty.example/widget@1.4.0/widget.css"
      integrity="sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z"
      crossorigin="anonymous">
```
```
# Back SRI with a strict Content-Security-Policy that also requires it
Content-Security-Policy:
  default-src 'self';
  script-src 'self' https://cdn.thirdparty.example;
  style-src  'self' https://cdn.thirdparty.example;
  require-sri-for script style;
  object-src 'none'; base-uri 'none'
```
```
# Compute the SRI hash for the exact file you are pinning:
$ curl -s https://cdn.thirdparty.example/analytics@3.2.1/analytics.js \
    | openssl dgst -sha384 -binary | openssl base64 -A
# Prefix with "sha384-" in the integrity attribute.
```

## Next Steps

- **[Prevention](prevention.html)**: The full layered strategy behind these snippets.
- **[Attack Vectors](attack-vectors.html)**: The attacks each secure example blocks.
- **[Overview](overview.html)**: Concepts, impact, and relationship to A06:2021.
- **[Hands-On Lab](./lab/software-supply-chain-failures/)**: Turn a vulnerable setup into a hardened one, step by step.
