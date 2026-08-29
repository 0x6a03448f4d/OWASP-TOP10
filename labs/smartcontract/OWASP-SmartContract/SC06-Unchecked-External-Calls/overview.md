# SC06: Unchecked External Calls - Overview

## Table of Contents

- [What Are Unchecked External Calls?](#what-is-unchecked-external-calls)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Statistics](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What Are Unchecked External Calls?

**Unchecked External Calls** occur when a smart contract makes a low-level call to another address—to send ether, invoke a function, or move tokens—and then *ignores whether that call actually succeeded*. The contract continues executing as if the interaction worked, updating balances, marking payments complete, or emitting success events, even though the external operation may have silently failed.

On the EVM, not every failure reverts your transaction. Some primitives signal failure by returning a boolean `false` instead of throwing. If you never read that boolean, the failure is invisible: execution rolls forward on a false assumption. The gap between "the call was attempted" and "the call succeeded" is exactly where this vulnerability class lives.

### Core Concept

```
Unchecked (dangerous):
  recipient.send(amount);              // returns false on failure, NOT checked
  recipient.call{value: amount}("");   // returns (bool, bytes), return VALUE ignored
  token.transfer(to, amount);          // non-standard token returns false, ignored
  target.delegatecall(data);           // success flag discarded
  --> contract updates state as if everything worked

Checked (safe):
  (bool ok, ) = recipient.call{value: amount}("");
  require(ok, "ETH transfer failed");  // failure reverts the whole tx
  token.safeTransfer(to, amount);      // SafeERC20 reverts on false/empty return
  (bool ok2, bytes memory ret) = target.delegatecall(data);
  require(ok2, "delegatecall failed"); // success AND returned data verified
  --> state changes only happen when the call truly succeeded
```

### Why It's Critical for Smart Contracts

Smart contracts hold value directly and their state is the ledger. Several conditions make ignoring a call result especially damaging:

- They are **immutable once deployed**—a silent-failure accounting bug cannot be hot-patched; funds can be stranded permanently.
- They **interact constantly with untrusted external code**—recipients can be contracts that reject ether, revert deliberately, or consume all forwarded gas.
- They **integrate arbitrary tokens**, many of which do not follow the ERC-20 return-value convention exactly, so "it worked in testing with token X" does not generalise.
- Their **state is the money**—crediting or debiting a balance after a transfer that never landed either strands funds or lets them be double-spent.

## Why Does This Matter?

### Business Impact

- **Stuck or Lost Funds**: A withdrawal whose transfer silently fails while the internal balance is still zeroed leaves the user unable to recover their ether or tokens.
- **Accounting Corruption**: If a payout is marked "paid" but the money never left, the protocol's internal books diverge from reality—every downstream calculation is now wrong.
- **Double-Spend and Theft**: A deposit that assumes `transferFrom` succeeded, when it returned `false`, credits tokens the contract never received—an attacker mints internal balance for free.
- **Broken Integrations**: Non-standard tokens (USDT-class, and tokens that return nothing) cause reverts or silent no-ops that brick vaults, exchanges, and payment flows.
- **Irreversible and Public**: On-chain, the failure and its consequences are permanent and visible; recovery usually requires a migration or a social bailout.

### Technical Impact

- **Silent State Divergence**: The contract's storage records an outcome that never happened on-chain.
- **Value Locked**: Ether or tokens accumulate in a contract with no code path able to release them correctly.
- **Phantom Credit**: Internal balances are increased for transfers that did not actually move value in.
- **Failed delegatecall Masked**: A proxy or library `delegatecall` that reverts is treated as a successful upgrade or execution, corrupting the caller's storage assumptions.
- **Partial Failure**: In batch operations, one leg failing without a check leaves the batch half-applied.

## Technical Context

### The EVM Call Primitives and How They Signal Failure

| Primitive | On failure | Must you check? |
| --- | --- | --- |
| `address.transfer(x)` | Reverts (throws) | Auto-checked, but forwards only 2300 gas |
| `address.send(x)` | Returns `false` | **Yes** — you must read the bool |
| `address.call{value:x}("")` | Returns `(false, ...)` | **Yes** — the bool is ignored by default |
| `address.delegatecall(data)` | Returns `(false, ...)` | **Yes** — success and return data |
| `address.staticcall(data)` | Returns `(false, ...)` | **Yes** — the bool is ignored by default |
| High-level `Contract(x).f()` | Reverts (bubbles up) | Auto-checked by the compiler |

The trap is that `send`, `call`, `delegatecall`, and `staticcall` return their success as a value rather than reverting. Solidity even emits a compiler warning if you discard the return value of a low-level call—because doing so is almost always a bug.

### Common Vulnerable Patterns

#### 1. Ignoring the Boolean Return of call

```
// The (bool) return is silently dropped: a failed transfer looks successful.
function withdraw(uint256 amount) external {
    balances[msg.sender] -= amount;
    msg.sender.call{value: amount}("");   // return value NOT captured
    emit Withdrawn(msg.sender, amount);   // emitted even if the ETH never left
}
```

#### 2. Using send Without Reading the Result

```
// send() returns false on failure and does NOT revert.
function payout(address payable to, uint256 amount) external {
    to.send(amount);           // if this returns false, we never notice
    paid[to] = true;           // marked paid regardless of the real outcome
}
```

#### 3. Assuming ERC-20 transfer/transferFrom Reverts on Failure

```
// Many real tokens return false (or nothing) instead of reverting.
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount); // return ignored
    deposited[msg.sender] += amount;   // credited even if transferFrom returned false
}
```

The ERC-20 standard says `transfer` and `transferFrom` return a `bool`. A large population of deployed tokens either return `false` on failure without reverting, or return *no data at all* (the "USDT-class" non-standard tokens). Code that assumes a revert-on-failure and never inspects the return value will credit balances for transfers that never happened.

#### 4. Unchecked delegatecall

```
// A failed delegatecall to a library/implementation is treated as success.
function execute(address impl, bytes calldata data) external onlyOwner {
    impl.delegatecall(data);   // success flag discarded; storage may be corrupted
}
```

#### 5. State Changes After a Silently-Failed Transfer

```
// The order and the missing check together strand funds.
function claim() external {
    uint256 owed = rewards[msg.sender];
    rewards[msg.sender] = 0;             // effect applied first
    msg.sender.send(owed);              // if send() fails, reward is gone forever
}
```

### Why "It Reverts, So I'm Safe" Is Wrong

The high-level typed call `IERC20(t).transfer(...)` compiles to a low-level call plus a check that the call itself did not revert—but for a token that returns `false` without reverting, the call *succeeds at the EVM level* while reporting `false` in its return data. Unless you also decode and require that boolean, the failure slips through. This is precisely what `SafeERC20` was created to handle.

## Real-World Impact

### Incident Class 1: Silent-Transfer-Failure Accounting Bugs

**Pattern**:

- A contract sends ether with `send` or an unchecked `call` during a withdrawal or payout and updates internal state as if it succeeded.
- The recipient is a contract that rejects the transfer (no payable fallback, a reverting fallback, or one that exceeds the forwarded gas), so the transfer returns `false`.

**Impact**:

- The internal balance is zeroed or the payment is flagged complete while the value never left the contract—funds become stranded, and the accounting no longer matches the on-chain reality.

**Root Cause**: A low-level transfer whose boolean result was never checked, combined with state updates that assume success. The durable lesson is that *every* value-moving call must have its result verified before state is treated as final.

### Incident Class 2: Non-Standard Token Integration Failures

**Pattern**:

- A vault, DEX, or lending contract integrates a token assuming strict ERC-20 semantics (return `true` or revert).
- The token instead returns `false`, or returns no data at all, on a failed or even a normal transfer.

**Impact**:

- Deposits are credited without the tokens ever arriving (phantom balance), or the integration reverts unexpectedly and locks the market—depending on how the return value is (mis)handled.

**Root Cause**: Treating a heterogeneous token population as if it were uniformly standard-compliant, and not reading (or not tolerating) the actual return data. `SafeERC20`-style wrappers exist specifically because this class of integration bug is so common.

### Incident Class 3: Masked delegatecall / Proxy Failures

**Pattern**:

- A proxy or "multicall"/executor contract performs a `delegatecall` (or `call`) into an implementation and does not check the returned success flag.

**Impact**:

- A reverting or no-op implementation is treated as a successful operation; the caller records an outcome (upgrade applied, action executed) that did not happen, corrupting its own storage assumptions.

**Root Cause**: Discarding the `(bool success, bytes data)` tuple that low-level calls return, instead of requiring success and, where relevant, validating the returned data.

## Prevalence and Statistics

Unchecked External Calls is ranked **SC06 in the OWASP Smart Contract Top 10 (2025)**. It is a persistent finding in audits because it hides in ordinary-looking code: a single missing `require` around a transfer is easy to write and easy to miss in review.

Rather than cite precise loss figures (which vary by source and incident), the defensible picture is:

- Missing return-value checks on `send`/`call` and unsafe ERC-20 handling are among the **most frequently reported low-to-high severity issues** in Solidity audits.
- Automated analysers (Slither's `unchecked-lowlevel`/`unchecked-send`, MythX, and the Solidity compiler's own "return value ignored" warning) flag this class routinely—evidence of how common it is.
- Severity ranges from **funds permanently stuck** (silent withdrawal failure) up to **direct value theft** (phantom deposits from non-standard tokens).

Note: exact loss totals differ between reports and years. Treat any single figure as illustrative; the durable takeaway is that unchecked calls are common, easy to introduce, and can either strand or steal funds.

## Common Misunderstandings

### Myth 1: "Low-level calls revert on failure like normal function calls"

**Reality**: `call`, `send`, `delegatecall`, and `staticcall` return a boolean success flag instead of reverting. If you do not read that flag, a failed call looks identical to a successful one.

### Myth 2: "ERC-20 transfer always returns true or reverts"

**Reality**: Many widely-used tokens return `false` on failure without reverting, and some return no data at all. Assuming uniform behaviour is how phantom deposits and stuck integrations happen. Use `SafeERC20`.

### Myth 3: "Checking the return value is optional gas optimisation"

**Reality**: The check is a correctness requirement, not an optimisation. Skipping it is the vulnerability; the few gas units saved are irrelevant next to stranded or stolen funds.

### Myth 4: "transfer() (which auto-reverts) is always the safe choice"

**Reality**: `address.transfer` does revert on failure, but it forwards a fixed 2300 gas stipend, which breaks recipients whose fallback needs more gas (e.g. some smart-contract wallets). Modern guidance prefers a checked `call` with a reentrancy guard over the rigid `transfer`/`send` stipend.

### Myth 5: "If the transfer failed, at least nothing bad happened"

**Reality**: When state was already updated (balance zeroed, payment marked complete), a silent failure is worse than a revert—the books now lie, and the value may be unrecoverable.

### Myth 6: "A successful delegatecall return flag means the returned data is valid"

**Reality**: Success only means the call did not revert. For calls that are supposed to return data (e.g. a token's `bool`), you must also decode and validate that data before acting on it.

## How Unchecked External Calls Differ from Related Issues

| Aspect | Unchecked External Calls (SC06) | Reentrancy (SC05) | Access Control (SC01) |
| --- | --- | --- | --- |
| **Root cause** | Ignoring a call's success/return value | State changed after an external call | Missing/incorrect permission checks |
| **Symptom** | Silent failure, stuck or phantom funds | Re-entered function drains balance | Unauthorized action succeeds |
| **Typical fix** | Check return value; use SafeERC20 | CEI ordering + reentrancy guard | Enforce roles/ownership |
| **Detection** | Return-value/linter warnings | Call-then-write analysis | Modifier/role audit |

## Key Takeaways

1. **Not every failure reverts**—`send`, `call`, `delegatecall`, and `staticcall` return a boolean you must read.
2. **The return value is correctness, not optimisation**—always `require` success before treating state as final.
3. **Tokens are not uniform**—assume non-standard behaviour and use `SafeERC20` for `transfer`/`transferFrom`/`approve`.
4. **Order and checks together matter**—follow Checks-Effects-Interactions and verify the interaction result.
5. **Silent failure can be worse than a revert**—it strands funds or mints phantom balances while the books say everything is fine.

## How to Identify if You're Vulnerable

Ask these questions about your contracts:

- [ ] Is the boolean return of every `call`/`send`/`delegatecall`/`staticcall` captured and required?
- [ ] Do you use `SafeERC20` (`safeTransfer`/`safeTransferFrom`/`safeApprove`) for all token movements?
- [ ] Do you assume any token reverts on failure without also checking its return data?
- [ ] Are state changes applied only *after* confirming the external interaction succeeded (or safely reverted)?
- [ ] Do you verify both the success flag *and* the returned data of `delegatecall`/`call` where data is expected?
- [ ] Are partial failures in batch operations detected and handled explicitly?
- [ ] Have you considered pull-over-push so a single failing recipient cannot brick a payout loop?
- [ ] Do you surface failures with clear custom errors rather than swallowing them?

If you answered "no" or "not sure" to several of these, you likely have an exploitable unchecked-call bug today.

## Next Steps

- **Attack Vectors**: How silent call failures are triggered and abused
- **Prevention**: Return-value checks, SafeERC20, CEI, and pull-over-push
- **Examples**: Vulnerable vs. secure Solidity, side by side
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
