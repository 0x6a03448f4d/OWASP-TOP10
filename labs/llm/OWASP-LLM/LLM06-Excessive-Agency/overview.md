# LLM06:2025 Excessive Agency — Overview

## Table of Contents

- What is Excessive Agency?
- The Three Roots: Functionality, Permissions, Autonomy
- Why Does This Matter?
- Technical Context
- Real-World Impact
- Prevalence
- Common Misunderstandings
- Relationship to Other LLM Risks
- Self-Assessment
- Next Steps

## What is Excessive Agency?

**Excessive Agency** is the harm that follows when an LLM-based system is granted too much ability to *act*—too many tools, too much permission, or too much autonomy—so that an unexpected, ambiguous, or adversarially manipulated model output is able to trigger a damaging action in the real world. The vulnerability is not the wrong word in a chat reply; it is the wrong *side effect*: an email sent, a row deleted, a payment made, a server rebooted.

The distinction matters because an ordinary LLM that only produces text is bounded by its output channel—the worst case is a bad answer a human can ignore. The moment you connect that same model to tools, functions, plugins, APIs, shells, or downstream agents, its *words become actions*. Language models are non-deterministic and steerable by whoever controls their input, so any authority you hand the model is authority you have implicitly handed to every source of text that reaches its context window, including untrusted documents, web pages, emails, and tool results.

OWASP frames Excessive Agency as excessive **functionality, permissions, or autonomy**. Critically, the model itself does not have to be “jailbroken” for this to bite. A perfectly benign, well-behaved model can still cause catastrophic damage if it is wired to over-broad tools and allowed to fire them without a check. Excessive Agency is fundamentally a *design and architecture* flaw in the agentic scaffolding around the model, not a flaw inside the weights.

> **Working definition:** Excessive Agency exists whenever the blast radius of a single model decision exceeds what the situation actually requires—when the system *can* do more, to more things, with less oversight, than the task in front of it justifies.

## The Three Roots: Functionality, Permissions, Autonomy

Every instance of Excessive Agency traces back to one or more of three independent root causes. Treating them separately is useful because each has a different fix.

### 1. Excessive Functionality
The agent is given tools (or tools with capabilities) it does not need for its purpose. A support agent that only needs to *read* a knowledge base is handed a generic database tool that can also run arbitrary SQL. A tool built for one function exposes a dozen others as a side effect. Left-over experimental plugins remain callable in production. Every extra tool is extra attack surface: an input that should never reach a destructive capability now has a path to it.

### 2. Excessive Permissions
The tools the agent has are individually necessary, but each is scoped far more broadly than the task requires. A document-summariser’s database credential has `UPDATE`, `DELETE`, and `DROP` rights when `SELECT` on one table would do. A calendar tool holds full mailbox read/write. Worst of all, the tool authenticates as a single shared high-privilege service account, so the model acts with the union of every user’s rights and the identity of the *current* user is lost entirely.

### 3. Excessive Autonomy
The agent is permitted to execute high-impact, irreversible actions with no human confirmation and no independent authorisation check. There is no approval gate before it sends the message, moves the money, or deletes the records. The system treats the model’s intention as sufficient authority, so a single hallucinated or injected instruction flows straight through to execution.

```
Root cause          Question it answers                     Fix in one line
------------------  --------------------------------------  ------------------------------
Functionality       "Can the agent even reach this action?" Remove the tool / capability
Permissions         "How far does the action reach?"        Least-privilege scope the tool
Autonomy            "Who signs off before it fires?"        Require human / policy approval
```

## Why Does This Matter?

### Business Impact
- **Irreversible operational damage**: Deleted records, wiped mailboxes, and cancelled orders cannot always be undone. Unlike a data *leak*, a destructive *action* may have no clean rollback.
- **Financial loss**: Agents with payment, refund, trading, or procurement tools can move money on a single bad decision, at machine speed and machine scale.
- **Unauthorised outbound communication**: Agents that can email, post, or message can exfiltrate data or send fraudulent instructions in the organisation’s name, damaging trust and reputation.
- **Compliance and legal exposure**: Actions taken without a valid user-authorisation context (GDPR data deletion, HIPAA record changes, financial transactions) create regulatory liability and break audit requirements.
- **Loss of accountability**: When an agent acts through a shared service account, logs cannot attribute the action to the human who triggered it—forensics and non-repudiation collapse.

### Technical Impact
- **Prompt injection becomes remote code / remote action execution**: Excessive Agency is what converts a text-level injection (LLM01) into a real-world effect. The injection is the trigger; the agency is the loaded weapon.
- **Privilege escalation**: An over-scoped or shared-credential tool lets a low-privileged user, or an attacker who controls any text the model reads, act with the tool’s full privileges.
- **Lateral movement and chaining**: One tool’s output feeds the next tool’s input, so a single manipulated step can cascade—read secrets, then use them, then exfiltrate—without any human in the loop.
- **Complete-mediation failure**: If authorisation is checked only in the UI or only by trusting the model’s assertion (“the user is an admin”), the tool boundary itself performs no check and can be driven by manipulated input.

## Technical Context

### How an agent actually acts
A typical tool-using agent runs a loop: the model receives a goal plus a list of available tools (with names, descriptions, and argument schemas); it emits a structured “tool call” (a function name and JSON arguments); the orchestrator executes that call against a real system; the result is appended to the context; and the loop repeats until the model decides it is done. Excessive Agency lives entirely in step three—*the orchestrator executes*—because that is where model text turns into consequence.

```
User goal ─▶ [ LLM ] ─▶ tool_call{name, args} ─▶ [ ORCHESTRATOR ] ─▶ REAL SYSTEM
                ▲                                        │
                └──────────── tool result ◀─────────────┘
                             (untrusted text re-enters the context here)

The security question is never "did the model say the right thing?"
It is "should THIS call, with THESE args, in THIS context, be allowed to run at all?"
```

### Why the model cannot be trusted as the gatekeeper
The model’s context window is an open channel. Tool results, retrieved documents, web content, and user messages all arrive as text, and the model cannot reliably tell a legitimate instruction from an injected one embedded in a fetched web page or a support ticket. Any authorisation logic that lives *inside* the prompt (“only call `delete_user` if the requester is an admin”) is advisory at best: it is one sentence competing with everything else in the context, and an attacker’s sentence may win. Authorisation must therefore live *outside* the model, at the tool boundary, enforced by code that the model cannot talk its way past.

### The five ingredients of a damaging incident
1. A tool exists that can cause harm (functionality).
2. That tool is scoped to reach valuable or destructive operations (permissions).
3. The tool fires without an independent check (autonomy).
4. An input—user, document, or tool result—steers the model toward the harmful call (trigger, usually LLM01 prompt injection).
5. The output is handled and executed without validation (linking to LLM05, Improper Output Handling).
Remove any one ingredient and the incident is contained. Defence-in-depth for Excessive Agency is precisely the discipline of denying attackers all five at once.

## Real-World Impact

These are *classes* of incident that are well documented across the security-research community and vendor advisories. Specific figures vary by source, so we describe the mechanism rather than cite precise numbers.

### Indirect prompt injection driving agent actions
Researchers have repeatedly demonstrated that content an agent merely *reads*—a web page, a shared document, an email, a calendar invite, an image with hidden text—can carry instructions that the agent then executes with its own tools. When those tools include sending mail or reading private data, the read-only act of “summarise my inbox” becomes a data-exfiltration path. This class underlies most published attacks on email assistants, browsing agents, and IDE/coding assistants.

### Over-privileged database and infrastructure tools
A recurring finding is agents wired to database or cloud credentials with write/delete/admin rights when the use case only reads. A single ambiguous instruction (“clean up the test records”) or an injected one can then destroy production data. The vulnerability is the credential scope, not the phrasing.

### Confused-deputy and shared-credential escalation
Agents that act through one shared high-privilege identity let any user reach data or actions they personally should not. Because the tool sees only the agent’s identity, per-user access control silently disappears—a classic confused-deputy problem re-created inside AI plumbing.

### Autonomous chains without a stop
Multi-step and multi-agent systems that plan-and-execute without checkpoints have been shown to take long chains of consequential actions from a single prompt, amplifying any early mistake. The absence of an approval gate is what turns one wrong step into many.

> Note: attack details and impact severity differ between reports and evolve quickly. Treat any single demonstration as illustrative. The durable takeaway is that every one of these classes is a failure of tool design and authorisation—not a failure the model could have prevented by “being smarter.”

## Prevalence

Excessive Agency was promoted in the **OWASP Top 10 for LLM Applications 2025** precisely because the industry moved from chat interfaces to *agents*: tool use, function calling, plugins, autonomous planners, and multi-agent orchestration became mainstream. As agentic frameworks (function calling, tool/plugin ecosystems, and orchestration libraries) proliferated, so did the wiring mistakes that create Excessive Agency.
- It is **increasingly common**: nearly every production “AI agent” grants some tool access, and least-privilege scoping is frequently skipped in the rush to ship.
- It is **easy to introduce**: default database users, broad OAuth scopes, and “give the agent admin so it just works” are the path of least resistance.
- Its impact ranges from **moderate to critical**—from a single unwanted email up to full data destruction or funds transfer.

## Common Misunderstandings

### Myth 1: “If the model is well-aligned, we don’t need guardrails on its tools.”
**Reality**: Alignment reduces *intent* to misbehave; it does nothing about *manipulation*. A cooperative model faithfully follows injected instructions it cannot recognise as malicious. Guardrails belong at the tool boundary, not in the model’s good manners.

### Myth 2: “Excessive Agency is just prompt injection.”
**Reality**: Prompt injection (LLM01) is the most common *trigger*, but Excessive Agency is the *impact enabler*. An agent with no destructive tools and human approval on everything can be injected all day and still cause little harm. They are distinct risks that compound.

### Myth 3: “We check the user’s permission in the chat UI, so the tools are safe.”
**Reality**: The tool call is a separate request the model can shape freely. If the tool itself does not re-verify the acting user’s authorisation, the UI check is bypassed the moment input steers the model. Enforce authorisation *downstream*, at the tool.

### Myth 4: “A human is technically in the loop, so we’re fine.”
**Reality**: A human who is shown a wall of “Approve?” dialogs and clicks yes reflexively provides no protection (“approval fatigue”). Human-in-the-loop only works when it is reserved for genuinely high-impact, irreversible actions and the human is given the information to decide.

### Myth 5: “More capable agents need more tools and more freedom.”
**Reality**: Capability comes from the *right* tools, well-scoped, not from a large undifferentiated toolbox. Minimising functionality usually improves reliability *and* security at once.

### Myth 6: “Read-only tools are harmless.”
**Reality**: Read tools enable exfiltration and reconnaissance, and their *output* re-enters the model as untrusted text that can carry the next injected instruction. Read access is lower risk, not no risk.

## Relationship to Other LLM Risks

| Risk | Relationship to Excessive Agency |
| --- | --- |
| **LLM01 Prompt Injection** | The usual *trigger*. Injection steers the model; agency lets that steering cause real damage. Fixing one without the other leaves the system exposed. |
| **LLM05 Improper Output Handling** | The *hand-off*. If a tool consumes the model’s output without validation, an ambiguous or malicious call executes. Complete mediation at the tool boundary is shared ground. |
| **LLM02 Sensitive Information Disclosure** | Over-broad read tools plus autonomy turn agency into an exfiltration channel. |
| **LLM08 Vector/Embedding & LLM04 Data Poisoning** | Poisoned retrieved content is a delivery vehicle for the injected instruction that abuses the agent’s tools. |

## Self-Assessment

Ask these questions about your agentic system:
- [ ] Does every tool the agent can call have a concrete, current reason to exist—or are there left-over/experimental capabilities still reachable?
- [ ] Is each tool scoped to the minimum operation (read vs. write vs. delete) the task needs, rather than a broad or admin credential?
- [ ] Does the agent act as the *end user’s* identity, or through a single shared high-privilege service account?
- [ ] Do high-impact or irreversible actions (send, pay, delete, deploy) require explicit human or policy approval before execution?
- [ ] Does each tool re-verify the acting user’s authorisation itself, instead of trusting the model’s assertion of who the user is or what they may do?
- [ ] Are tool actions rate-limited, sandboxed, and bounded (row limits, spend caps, allow-lists) so a runaway loop is contained?
- [ ] Is every tool invocation logged with the real user, arguments, and result, in a way an attacker cannot suppress?
- [ ] When a tool call is ambiguous, denied, or fails, does the system *fail safe* (stop and ask) rather than guess and proceed?
Several “no” or “not sure” answers indicate exploitable Excessive Agency today.

## Next Steps

- **[Attack Vectors](attack-vectors.html)**: How manipulated and ambiguous output is turned into damaging tool actions.
- **[Prevention](prevention.html)**: Layered, code-level defences—minimise, scope, gate, mediate, monitor, fail safe.
- **[Examples](examples.html)**: Vulnerable vs. secure agent and tool code in Python (LangChain / function calling) and Node/TypeScript.
- **[Hands-On Lab](./lab/excessive-agency/)**: Practise exploiting and then containing an over-agentic assistant.
