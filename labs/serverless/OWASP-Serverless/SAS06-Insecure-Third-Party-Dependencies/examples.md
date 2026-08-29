# SAS-6: Insecure Third-Party Dependencies - Code Examples

Each pair below shows a **vulnerable** setup and the **secure** version of the same thing—package configuration, lockfiles and hashes, CI scanning, and Lambda layer/dependency handling. The focus is the choices that decide whether a bad package can enter, and what it can do once it does.

## 1. Package Configuration (package.json / requirements.txt)

### Vulnerable
```
# package.json — floating ranges + a build-time script that runs anything
{
  "name": "order-fn",
  "dependencies": {
    "left-pad": "*",              // whatever resolves — no ceiling
    "some-parser": "^1.0.0",      // silently accepts a hijacked 1.9.9
    "aws-sdk": "latest"           // non-deterministic across builds
  },
  "scripts": {
    "postinstall": "node ./setup.js"   // arbitrary code on every install
  }
}

# requirements.txt — unpinned, no hashes
requests
pyyaml>=3
some-utils            # name never verified; a typo installs an impostor
```

### Secure
```
# package.json — exact-ish, no floating "latest", scripts controlled in CI
{
  "name": "order-fn",
  "dependencies": {
    "some-parser": "1.4.2",       // exact version, chosen deliberately
    "@aws-sdk/client-dynamodb": "3.658.1"
  }
  // no lifecycle scripts here; CI installs with --ignore-scripts
}

# requirements.txt — pinned AND hash-verified
requests==2.32.3 \
    --hash=sha256:70761cfe03c773ceb22aa2f671b4757976145175cdfca038c02654d061d6dcc6
pyyaml==6.0.2 \
    --hash=sha256:9b22676e8097e9e22e36d6b7bda33190d0d400f345f23d4065d48f4ca7ae0425
# Every package pinned; install fails if a hash does not match.
```

## 2. Lockfiles and Integrity Hashes

### Vulnerable
```
# CI installs with the mutable command and no lockfile discipline
npm install                     # may update the lockfile / pull new versions
# (package-lock.json not committed, or ignored in CI)

# Python
pip install -r requirements.txt # no --require-hashes; any matching version
```

### Secure
```
# Node — deterministic install straight from the committed lockfile
npm ci                          # fails if package-lock.json is missing/out of sync
# package-lock.json pins each dep with an integrity hash:
#   "some-parser": {
#     "version": "1.4.2",
#     "integrity": "sha512-Xa9...=="   // artifact is verified on install
#   }

# Python — require a hash for every package (direct and transitive)
pip install --require-hashes -r requirements.txt
# A swapped or tampered artifact fails the hash check and aborts the build.
```

## 3. CI Dependency Scanning (SCA)

### Vulnerable
```
# .github/workflows/deploy.yml — no scanning; ship whatever installs
jobs:
  deploy:
    steps:
      - run: npm install
      - run: npx serverless deploy      // known CVEs ride along, unnoticed
```

### Secure
```
# .github/workflows/deploy.yml — scan gates the deploy
jobs:
  deploy:
    steps:
      - run: npm ci --ignore-scripts

      # Fail the build on known-vulnerable dependencies
      - run: npm audit --audit-level=high
      - run: npx snyk test --severity-threshold=high

      # Generate + scan an SBOM of what will actually ship
      - run: npx @cyclonedx/cyclonedx-npm --output-file sbom.json
      - run: grype sbom:sbom.json --fail-on high

      # Only deploy if every gate passed
      - run: npx serverless deploy

# Also run the SAME scans on a schedule against deployed artifacts,
# so a CVE disclosed after release still raises an alarm.
```

Python equivalent gate:
```
- run: pip install --require-hashes -r requirements.txt
- run: pip-audit -r requirements.txt --strict     # non-zero exit fails the job
```

## 4. Lambda Layer / Bundled Dependencies

### Vulnerable
```
# A shared layer built once, never re-scanned, pinned by many functions
build-layer.sh:
  pip install -r layer-requirements.txt -t python/   # unpinned, unscanned
  zip -r layer.zip python/
  aws lambda publish-layer-version --layer-name common-deps \
      --zip-file fileb://layer.zip

# serverless.yml — 40 functions attach the same stale layer
functions:
  orders:
    handler: orders.handler
    layers:
      - arn:aws:lambda:us-east-1:123456789012:layer:common-deps:7   # frozen, vulnerable
    runtime: python3.7        # deprecated / unpatched runtime
```

### Secure
```
# Build the layer deterministically, scan its CONTENTS, rebuild on a cadence
build-layer.sh:
  pip install --require-hashes -r layer-requirements.txt -t python/
  # Scan the built layer directory before publishing
  grype dir:./python --fail-on high
  trivy fs ./python --severity HIGH,CRITICAL
  zip -r layer.zip python/
  aws lambda publish-layer-version --layer-name common-deps \
      --zip-file fileb://layer.zip

# serverless.yml — supported runtime, layer version bumped as it is rebuilt
functions:
  orders:
    handler: orders.handler
    layers:
      - arn:aws:lambda:us-east-1:123456789012:layer:common-deps:12  # freshly scanned
    runtime: python3.12       # current, patched runtime
```

## 5. Bounding the Blast Radius (the Serverless Twist)

Even a perfectly scanned pipeline can be beaten by a zero-day. The final control is ensuring a compromised dependency inherits almost nothing.

### Vulnerable
```
# serverless.yml — the function role is a skeleton key
provider:
  name: aws
  iam:
    role:
      statements:
        - Effect: Allow
          Action: "*"           # a bad dep can do ANYTHING
          Resource: "*"
  environment:
    DB_PASSWORD: ${env:DB_PASSWORD}   # secret sits in plaintext env for any module to read
```

### Secure
```
# serverless.yml — least privilege + secrets out of plaintext env
provider:
  name: aws
  iam:
    role:
      statements:
        - Effect: Allow
          Action: ["dynamodb:GetItem"]                 # only what the handler needs
          Resource: "arn:aws:dynamodb:us-east-1:123456789012:table/Orders"
# Pull secrets at runtime from a secrets manager (short-lived), not plaintext env,
# and restrict egress so exfiltration has nowhere to go.
functions:
  orders:
    handler: orders.handler
    # install scripts disabled at build; deps pinned + scanned in CI (sections 1-4)
```

## What Changed, and Why

| Area | Vulnerable | Secure |
|------|------------|--------|
| Package config | Floating ranges (`*`, `latest`), `postinstall` on | Deliberate exact versions; scripts controlled in CI |
| Lockfiles / hashes | `npm install`, no committed lockfile, no hashes | `npm ci` / `--require-hashes` from a committed, hashed lockfile |
| CI scanning | None — CVEs ship silently | SCA + SBOM scan gate the deploy, and run on a schedule |
| Layers / runtime | Stale, unscanned layer; deprecated runtime | Scanned, rebuilt layer; current, patched runtime |
| Blast radius | `*` role, secret in plaintext env | Least-privilege role, secrets manager, egress limits |

## Next Steps

- **[Prevention](prevention.md)**: The full inventory, scanning, pinning, and least-privilege strategy
- **[Attack Vectors](attack-vectors.md)**: How these dependencies are exploited inside functions
- **[Serverless Learning Path](/learn/serverless)**: Continue the OWASP Serverless Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on exercises
