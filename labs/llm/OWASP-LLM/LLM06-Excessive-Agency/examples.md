# LLM06:2025 Excessive Agency — Examples

## Table of Contents

- How to Read These Examples
- Example 1: Over-Broad Tool (SQL)
- Example 2: No Approval on Irreversible Action
- Example 3: Shared Credentials vs. User Identity
- Example 4: LangChain Agent — Whole Toolbox vs. Scoped
- Example 5: Argument Injection (SSRF / Shell)
- Example 6: Node/TypeScript Function-Calling Gate
- Example 7: The Central Mediation Gate
- Next Steps

## How to Read These Examples
Each example pairs a realistic **vulnerable** implementation with a **secure** rewrite. The model in each case may be perfectly well-behaved—the flaw is in the *scaffolding* around it. Python (LangChain / function-calling style) is primary; Node/TypeScript appears where it reads naturally. Comments mark the exact line where model text turns into consequence.

## Example 1: Over-Broad Tool (SQL)
A support agent needs to look up order status. The vulnerable version exposes raw SQL; the secure version exposes one narrow, parameterised, read-only operation.

### Vulnerable
```
# ❌ VULNERABLE: a "lookup" tool that is really arbitrary SQL over an admin connection
from langchain.tools import tool
import psycopg2

conn = psycopg2.connect("postgres://admin:secret@db/app")   # full-privilege user

@tool
def query_database(sql: str) -> str:
    """Run a SQL query to answer the user's question."""
    with conn.cursor() as cur:
        cur.execute(sql)                 # ← ANY statement: SELECT, UPDATE, DROP …
        return str(cur.fetchall())

# Ambiguous or injected input →
#   query_database("SELECT password_hash FROM users")
#   query_database("DELETE FROM orders")           # irreversible, no gate
```

### Secure
```
# ✅ SECURE: one narrow capability, read-only role, parameterised, bounded
from langchain.tools import tool
from pydantic import BaseModel, Field
import psycopg2

# Least privilege: this role has SELECT on two tables only (see Prevention D2).
ro_conn = psycopg2.connect("postgres://agent_ro:pw@db/app")

class OrderStatusArgs(BaseModel):
    order_id: int = Field(gt=0)          # typed, validated — not free text

@tool(args_schema=OrderStatusArgs)
def get_order_status(order_id: int) -> str:
    """Return the status of a single order the caller is allowed to see."""
    with ro_conn.cursor() as cur:
        cur.execute(
            "SELECT status FROM orders WHERE id = %s LIMIT 1",   # parameterised
            (order_id,),
        )
        row = cur.fetchone()
    return row[0] if row else "not found"
# No path to other tables, no writes, no arbitrary SQL — the vector is gone.
```

## Example 2: No Approval on Irreversible Action
An assistant can email customers. The vulnerable version sends immediately on the model’s say-so; the secure version routes high-impact actions through a human-approval gate and creates a reversible draft.

### Vulnerable
```
# ❌ VULNERABLE: model output → email sent, no gate, arbitrary recipient/body
@tool
def send_email(to: str, subject: str, body: str) -> str:
    smtp.send(to=to, subject=subject, body=body)     # ← fires instantly
    return "sent"

# Indirect injection in a document the agent read can now email anyone anything,
# including exfiltrating context to an attacker address.
```

### Secure
```
# ✅ SECURE: recipient allow-list + human approval for a high-impact action
from pydantic import BaseModel, EmailStr

APPROVED_DOMAINS = {"ourcompany.com", "known-partner.com"}

class EmailArgs(BaseModel):
    to: EmailStr
    subject: str
    body: str

def send_email(ctx, args: EmailArgs) -> str:
    if args.to.split("@")[-1] not in APPROVED_DOMAINS:
        raise PermissionError("recipient domain not permitted")

    # High-impact + outbound → require an explicit, honest human approval.
    decision = approvals.request(
        actor=ctx.user_id, action="send_email",
        summary=f"Send to {args.to} — subj: {args.subject!r}",
        preview=args.body, reversible=False,
    )
    if not decision.approved:
        return "not sent — awaiting/denied human approval"

    draft_id = mail.create_draft(**args.dict(), actor=ctx.user_id)  # reversible artefact
    mail.send_draft(draft_id)
    audit.emit(ctx, "send_email", args.dict(), "sent")
    return "sent"
```

## Example 3: Shared Credentials vs. User Identity
The confused-deputy fix: act as the end user, not a shared powerful account, and let the downstream system enforce that user’s ACLs.

### Vulnerable
```
# ❌ VULNERABLE: every request uses one DBA-level service token
SERVICE_TOKEN = "svc-dba-omnipotent"

@tool
def read_hr_record(employee_id: str) -> str:
    # Downstream sees only the all-powerful service identity.
    return hr_api.get(employee_id, auth=SERVICE_TOKEN)   # tier-1 user now reads salaries
```

### Secure
```
# ✅ SECURE: propagate the USER's delegated token; downstream applies their ACLs
from dataclasses import dataclass

@dataclass(frozen=True)
class ActingContext:
    user_id: str
    token: str            # the end user's short-lived delegated token

def read_hr_record(ctx: ActingContext, employee_id: str) -> str:
    # If this user can't see the record, hr_api denies it — model can't override.
    return hr_api.get(employee_id, auth=ctx.token)
```

## Example 4: LangChain Agent — Whole Toolbox vs. Scoped
The most common real-world mistake: handing an agent a pile of powerful tools and full autonomy. The secure version registers only what the role needs and wraps execution in a gate.

### Vulnerable
```
# ❌ VULNERABLE: kitchen-sink toolbox, no mediation, autonomous execution
from langchain.agents import initialize_agent, AgentType

tools = [
    query_database,      # arbitrary SQL (Example 1)
    send_email,          # instant send (Example 2)
    run_shell,           # arbitrary commands
    http_request,        # arbitrary egress
    delete_records,      # irreversible
    __debug_exec,        # left over from development
]
agent = initialize_agent(tools, llm, agent=AgentType.OPENAI_FUNCTIONS)
agent.run(user_input)    # any injected instruction reaches any tool
```

### Secure
```
# ✅ SECURE: minimal approved tools + a mediation wrapper on every call
from langchain.agents import initialize_agent, AgentType

APPROVED = [get_order_status, create_ticket]     # nothing destructive by default

def mediated(tool):
    """Wrap a tool so EVERY invocation passes the central gate (Prevention D6)."""
    def run(args, ctx=current_context()):
        policy.check(ctx, tool, args)            # identity + authz + allow-lists
        budget.consume(ctx, tool.cost)           # step / spend limits
        validated = tool.args_schema(**args)     # strict validation
        with audit.record(ctx, tool.name, args):
            return tool.func(ctx, validated)
    return make_tool(tool.name, tool.description, tool.args_schema, run)

agent = initialize_agent(
    [mediated(t) for t in APPROVED], llm,
    agent=AgentType.OPENAI_FUNCTIONS,
    max_iterations=15,          # bound runaway loops
)
agent.run(user_input)
```

## Example 5: Argument Injection (SSRF / Shell)
Even a “narrow” tool is unsafe if attacker-controlled text flows into a dangerous argument.

### Vulnerable
```
# ❌ VULNERABLE: model text reaches a shell and an unrestricted URL fetch
@tool
def fetch(url: str) -> str:
    return requests.get(url).text            # SSRF: http://169.254.169.254/… reachable

@tool
def run_shell(command: str) -> str:
    return subprocess.check_output(command, shell=True).decode()   # RCE via injection
```

### Secure
```
# ✅ SECURE: egress allow-list; no shell — a fixed, enumerated action set
from urllib.parse import urlparse

ALLOWED_HOSTS = {"docs.internal", "kb.internal"}

def fetch(ctx, url: str) -> str:
    host = urlparse(url).hostname
    if host not in ALLOWED_HOSTS:               # blocks SSRF + exfiltration egress
        raise PermissionError("host not permitted")
    return http_get_no_redirects(url, timeout=5).text

# Replace arbitrary shell with a closed set of named, parameter-free operations.
SAFE_OPS = {"restart_worker": _restart_worker, "flush_cache": _flush_cache}

def run_op(ctx, op_name: str) -> str:
    fn = SAFE_OPS.get(op_name)
    if fn is None:
        raise PermissionError("unknown operation")    # no free-form command ever
    return fn(actor=ctx.user_id)
```

## Example 6: Node/TypeScript Function-Calling Gate
The same discipline in a TypeScript function-calling agent: validate arguments, check authorisation in code, gate high-impact actions.

### Vulnerable
```
// ❌ VULNERABLE: dispatch straight from the model's tool call
async function handleToolCall(call: { name: string; args: any }) {
  if (call.name === "deleteProject") {
    await db.projects.delete(call.args.id);      // no authz, no confirm, irreversible
  }
  return "done";
}
```

### Secure
```
// ✅ SECURE: schema validation + downstream authz + approval gate
import { z } from "zod";

const DeleteProjectArgs = z.object({ id: z.string().uuid() });
const HIGH_IMPACT = new Set(["deleteProject", "sendEmail", "makePayment"]);

async function handleToolCall(
  ctx: { userId: string; roles: Set<string>; token: string },
  call: { name: string; args: unknown },
) {
  if (call.name === "deleteProject") {
    const args = DeleteProjectArgs.parse(call.args);            // reject bad input

    if (!ctx.roles.has("project-admin"))                        // authz in code
      throw new Error("not authorized to delete projects");

    if (HIGH_IMPACT.has(call.name)) {                           // human approval
      const ok = await approvals.request(ctx.userId, call.name, args);
      if (!ok) return "not deleted — approval denied";
    }

    await db.projects.softDelete(args.id, ctx.token);          // reversible + attributed
    audit.emit(ctx.userId, call.name, args, "ok");
    return "deleted (soft)";
  }
  throw new Error("unknown tool");                              // default-deny
}
```

## Example 7: The Central Mediation Gate
All of the above converge on one idea: a single choke point every tool call flows through. This is the reference shape to build once and reuse everywhere.
```
# ✅ SECURE: one dispatch path — identity, authz, validation, budget, approval, audit
def dispatch(ctx, call):
    tool = registry.get(call.name)                     # 1. must be an approved tool
    if tool is None:
        raise Denied("default-deny: unknown tool")     #    fail safe

    policy.check(ctx, tool, call.args)                 # 2. downstream authorization
    budget.consume(ctx, tool.cost)                     # 3. rate / step / spend limits
    args = tool.schema.validate(call.args)             # 4. strict arg validation

    if tool.high_impact:                               # 5. human-in-the-loop
        if not approvals.request(ctx, call).approved:
            return Denied("human approval not granted")

    with audit.record(ctx, call):                      # 6. tamper-evident logging
        return tool.run(ctx, args)                     #    only now: real action
# The model can propose anything; only what survives this gate ever executes.
```

## Next Steps
- **[Prevention](prevention.html)**: The full rationale behind each control shown here.
- **[Attack Vectors](attack-vectors.html)**: The specific attacks these rewrites defeat.
- **[Overview](overview.html)**: Why the fix is architectural, not a better prompt.
- **[Hands-On Lab](./lab/excessive-agency/)**: Run the vulnerable code, exploit it, then apply the secure versions.
