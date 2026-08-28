# LLM06:2025 Excessive Agency — Prevention

## Table of Contents

- The Defence Model
- 1. Minimise Functionality
- 2. Least-Privilege Tool Scoping
- 3. Propagate User Identity (No Shared Creds)
- 4. Enforce Authorisation Downstream
- 5. Human-in-the-Loop for High-Impact Actions
- 6. Complete Mediation at the Tool Boundary
- 7. Validate & Constrain Tool Arguments
- 8. Rate-Limit, Budget & Sandbox
- 9. Fail Safe
- 10. Log, Monitor & Alert
- Implementation Checklist
- Next Steps

## The Defence Model

Excessive Agency is contained by shrinking the blast radius of any single model decision and inserting independent checks between the model’s intent and the real-world action. No control is sufficient alone; they are layered so that defeating one still leaves the attacker facing the next. Map each layer to the three roots and the core attack flow:

```
Root cause        Primary defences
----------------  --------------------------------------------------------------
Functionality  →  Minimise tools (D1)  ·  remove left-overs
Permissions    →  Least-privilege scope (D2)  ·  user identity (D3)  ·  downstream authz (D4)
Autonomy       →  Human-in-the-loop (D5)  ·  fail safe (D9)

Cross-cutting  →  Complete mediation (D6)  ·  arg validation (D7)  ·  rate/sandbox (D8)  ·  logging (D10)
```

> **Governing principle:** the model proposes, code disposes. Every consequential action passes through a policy layer the model cannot argue with, and that layer’s decision—not the model’s—is what executes.

## 1. Minimise Functionality
Give the agent the fewest tools, and the fewest capabilities per tool, that the job actually needs. Every removed capability is an attack vector deleted outright. Audit the registered tool list and strip anything experimental, debug, or “just in case.”
```
class Registry:
    """Only tools with a current, documented purpose may register."""
    def __init__(self, allowed: set[str]):
        self._allowed = allowed          # explicit allow-list, reviewed per release
        self._tools = {}

    def register(self, name, fn):
        if name not in self._allowed:
            raise ValueError(f"Tool {name!r} is not approved for this agent")
        self._tools[name] = fn

# Prefer one narrow tool over one broad tool:
#   BAD : run_sql(query)            → unbounded
#   GOOD: get_order_status(order_id) → one query, typed input, one table
```

## 2. Least-Privilege Tool Scoping
Each tool authenticates with the narrowest credential that lets it do its one job. If the task reads, the credential cannot write. If it writes one table, it cannot touch others. Never reuse a broad admin credential across tools.
```
# Database: a read tool gets a read-only role, scoped to specific tables.
# (PostgreSQL example)
CREATE ROLE agent_ro LOGIN PASSWORD :'pw';
GRANT CONNECT ON DATABASE app TO agent_ro;
GRANT USAGE  ON SCHEMA public TO agent_ro;
GRANT SELECT  ON public.orders, public.order_items TO agent_ro;   -- nothing else
-- No INSERT/UPDATE/DELETE, no other tables, no DDL.

# Cloud/OAuth: request the minimum scopes, short-lived tokens.
scopes = ["calendar.events.readonly"]     # not "calendar" (read/write everything)
```

## 3. Propagate User Identity (No Shared Creds)
The agent must act *as the end user*, not as one shared high-privilege service account. Pass the user’s identity/token down to each tool so downstream systems enforce that user’s real permissions. This kills the confused-deputy vector.
```
@dataclass(frozen=True)
class ActingContext:
    user_id: str
    roles: frozenset[str]
    token: str            # the USER's delegated token, not a service secret

def read_record(ctx: ActingContext, record_id: str):
    # The downstream API receives the user's token and applies THEIR ACLs.
    return records_api.get(record_id, auth=ctx.token)
    # If the user can't see it, the API denies it — regardless of what the model asked.
```

## 4. Enforce Authorisation Downstream
Never trust the model’s assertion of who the user is or what they may do. Re-check authorisation in code, at the tool, against the real acting context—treating any “the user is an admin” text in the prompt as untrusted.
```
def delete_user(ctx: ActingContext, target_id: str):
    # Authorization is decided HERE, by code — not by the LLM's say-so.
    if "user-admin" not in ctx.roles:
        raise PermissionError("caller is not authorized to delete users")
    if target_id == ctx.user_id:
        raise PermissionError("cannot delete self via agent")
    return users.soft_delete(target_id, actor=ctx.user_id)   # reversible + attributed
```

## 5. Human-in-the-Loop for High-Impact Actions
Classify actions by impact and reversibility. Low-impact, reversible actions may run autonomously; high-impact or irreversible ones (send, pay, delete, deploy, grant access) require explicit human approval—shown honestly, with the true target and scope. Reserve approvals for the few actions that matter to avoid fatigue.
```
HIGH_IMPACT = {"send_email", "make_payment", "delete_records", "deploy", "grant_access"}

def execute(ctx, call):
    if call.name in HIGH_IMPACT:
        # Present the REAL action; never a sanitized summary the model wrote.
        if not approvals.request(
            actor=ctx.user_id, action=call.name, args=call.args,
            reversible=is_reversible(call), summary=render_true_effect(call),
        ).approved:
            return Denied("human approval not granted")
    return dispatch(ctx, call)
```

## 6. Complete Mediation at the Tool Boundary
Every tool call—without exception, on every path, including chained and multi-agent calls—passes through one central policy gate. No tool is dispatched directly. This is the single choke point where identity, authorisation, scope, budget, and approval are enforced together.
```
def dispatch(ctx, call):
    tool = registry.get(call.name)                 # must be a registered tool
    policy.check(ctx, tool, call.args)             # identity + authz + allow-lists
    budget.consume(ctx, tool.cost)                 # rate/step/spend limits
    args = tool.schema.validate(call.args)         # strict typed validation (D7)
    with audit.record(ctx, call):                  # tamper-evident log (D10)
        return tool.run(ctx, args)                 # only now does it touch reality
# There is NO other way to invoke a tool. Every route goes through here.
```

## 7. Validate & Constrain Tool Arguments
Treat every argument the model emits as untrusted. Enforce strict typed schemas, allow-lists, ranges, and formats. Never feed model output into a shell, `eval`, a raw SQL string, or an unrestricted URL.
```
from pydantic import BaseModel, field_validator

ALLOWED_HOSTS = {"docs.internal", "kb.internal"}

class FetchArgs(BaseModel):
    url: str
    @field_validator("url")
    @classmethod
    def only_allowed(cls, v):
        host = urlparse(v).hostname
        if host not in ALLOWED_HOSTS:               # egress allow-list → blocks SSRF
            raise ValueError("host not permitted")
        return v

# SQL: parameterised, never string-built from model text.
db.execute("SELECT status FROM orders WHERE id = %s", (args.order_id,))
```

## 8. Rate-Limit, Budget & Sandbox
Bound how much an agent can do before a human notices: per-session step budgets, per-tool rate limits, spend caps, row/size limits, and time-outs. Run risky tools in a sandbox (isolated container, no ambient credentials, restricted network) so a bad call cannot reach beyond its box.
```
class Budget:
    def __init__(self, max_steps=25, max_spend_cents=500):
        self.steps, self.max_steps = 0, max_steps
        self.spend, self.max_spend = 0, max_spend_cents
    def consume(self, ctx, cost):
        self.steps += 1
        if self.steps > self.max_steps:
            raise Halt("step budget exceeded — stopping and escalating to human")
        self.spend += cost.cents
        if self.spend > self.max_spend:
            raise Halt("spend cap exceeded")

# Destructive queries get hard bounds even when authorized:
#   DELETE ... LIMIT 100     require an explicit WHERE     dry-run count first
```

## 9. Fail Safe
When a call is ambiguous, denied, times out, or errors, the system must *stop and ask*—never guess and proceed. Default-deny at the policy gate: an action is allowed only if a rule explicitly permits it. Prefer reversible operations (soft-delete, drafts, staged changes) so mistakes are recoverable.
```
def check(ctx, tool, args):
    rule = policy_rules.get((tool.name, ctx.roles))
    if rule is None:
        raise Denied("default-deny: no rule permits this action")   # fail closed
    if rule.requires_confirmation and not args.get("_confirmed"):
        raise NeedsConfirmation(tool.name)     # stop → ask a human, don't assume "yes"
```

## 10. Log, Monitor & Alert
Record every tool invocation with the *real* acting user, the tool, the arguments, the decision, and the result—in append-only/tamper-evident storage the agent cannot edit. Alert on anomalies: destructive calls, egress to new hosts, spikes in tool volume, repeated denials (a sign of probing). Logs are how you detect and reconstruct an incident that slipped past the gates.
```
audit.emit({
    "ts": now(), "user_id": ctx.user_id, "tool": call.name,
    "args": redact(call.args), "decision": decision, "result_status": status,
    "session": ctx.session_id,
})
# Alert rules:
#   - any HIGH_IMPACT tool executed without a matching approval record
#   - egress host not in allow-list
#   - > N tool calls / minute for one session
#   - repeated PermissionError (enumeration / injection probing)
```

## Implementation Checklist
- [ ] Tool list is an explicit, reviewed allow-list; no debug/experimental/left-over tools are reachable.
- [ ] Each tool holds the minimum credential (read vs. write vs. delete), never a shared admin secret.
- [ ] The agent acts as the end user’s identity; the user’s token/permissions flow to every tool.
- [ ] Every tool re-checks authorisation in code; no decision relies on the model’s assertion.
- [ ] High-impact / irreversible actions require honest human approval; approvals are rare enough to stay meaningful.
- [ ] All tool calls pass through one central mediation gate—including chained and inter-agent calls.
- [ ] Arguments are validated against strict schemas/allow-lists; no model text reaches a shell, eval, raw SQL, or open URL.
- [ ] Step budgets, rate limits, spend caps, and sandboxing bound the blast radius.
- [ ] The gate is default-deny and fails safe (stop and ask) on ambiguity, denial, timeout, or error.
- [ ] Every action is logged with the real user in tamper-evident storage, with alerts on anomalies.

## Next Steps
- **[Examples](examples.html)**: See these controls applied in full vulnerable-vs-secure code.
- **[Attack Vectors](attack-vectors.html)**: The threats each layer is designed to stop.
- **[Overview](overview.html)**: The three roots and the core attack flow.
- **[Hands-On Lab](./lab/excessive-agency/)**: Apply the controls to a vulnerable agent and verify the attacks fail.
