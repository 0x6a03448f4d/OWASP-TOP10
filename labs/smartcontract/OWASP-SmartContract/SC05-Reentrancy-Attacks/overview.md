# SC05: Reentrancy Attacks - Overview

## Table of Contents
- [What is Reentrancy?](#what-is-reentrancy)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Significance](#prevalence-and-significance)
- [Common Misunderstandings](#common-misunderstandings)

## What is Reentrancy?

**Reentrancy** is a class of smart-contract vulnerability in which a contract makes an *external call*—sending ETH or invoking another contract—**before it finishes updating its own state**. The called party can then call back ("re-enter") into the original function while it is still mid-execution, observing and acting on **stale state** that has not yet been written back. Repeated re-entry against that stale state lets an attacker perform an action—most famously a withdrawal—many times when the contract intended to allow it only once.

The root cause is an ordering mistake. On most blockchains an external call transfers control synchronously to the callee, and the callee is free to run arbitrary code, including a call straight back into the caller. If the caller has not yet recorded the effects of what it is doing (for example, zeroing the user's balance), the world the callee sees is a lie: the balance still looks available, so the caller happily pays out again.

### Core Concept

```
Vulnerable ordering (Interactions BEFORE Effects):
  1. Check    -> require(balance[user] >= amount)
  2. Interact -> (bool ok, ) = user.call{value: amount}("")   <-- control leaves here
                   |                                              re-enters step 1
                   |  attacker's receive() calls withdraw() again, balance UNCHANGED
  3. Effect   -> balance[user] -= amount     <-- runs too late, many times over

Safe ordering (Checks-Effects-Interactions):
  1. Check    -> require(balance[user] >= amount)
  2. Effect   -> balance[user] -= amount     <-- state written FIRST
  3. Interact -> (bool ok, ) = user.call{value: amount}("")   <-- re-entry now sees 0
```

The difference between the two orderings is the whole vulnerability. In the first, the external call sits in the middle of an unfinished transaction; in the second, every state change the function promises has already happened before control ever leaves the contract, so a re-entrant call finds nothing left to steal.

### Why It's Critical for Smart Contracts

Several properties of blockchain execution make reentrancy uniquely dangerous:

- **Composability by design**: contracts are built to call one another. Any external call may hand control to attacker-controlled code, so "calling out" is never neutral.
- **Value moves synchronously**: a plain ETH transfer via `call` executes the recipient's `receive()`/`fallback()` in the same transaction, giving the recipient a hook to re-enter.
- **Immutability and finality**: once a draining transaction is mined it cannot be undone. There is no chargeback, and the code usually cannot be patched in place.
- **Funds are the payload**: the asset under attack is money held directly by the contract, so a single successful re-entry loop can drain the entire balance in one transaction.

## Why Does This Matter?

### Business Impact

- **Direct, irreversible loss of funds**: a reentrancy drain empties the contract's balance in a single transaction, and the transfer is final on-chain.
- **Protocol insolvency**: pools, vaults, and lending markets that lose their backing assets can no longer honour user withdrawals, wiping out every depositor at once.
- **Loss of trust and TVL flight**: a public reentrancy exploit triggers immediate withdrawal runs and lasting reputational damage across a protocol and its integrations.
- **Contagion across integrations**: because DeFi protocols read and depend on one another, a reentrancy bug in one contract (especially read-only reentrancy) can misprice or drain unrelated protocols that trusted its state.

### Technical Impact

- **Fund drainage**: repeated withdrawals against a balance that is never decremented until the loop ends.
- **Corrupted accounting**: cross-function reentrancy leaves internal ledgers (balances, shares, debt) inconsistent with the actual asset holdings.
- **Mispriced integrations**: read-only reentrancy makes a `view` getter return a stale price or share value mid-transaction, so an integrating protocol computes on wrong numbers.
- **Bypassed invariants**: one-time actions (claim once, mint once, vote once) execute many times because the "already done" flag is written after the external call.

## Technical Context

### The Classic Vulnerable Pattern

The canonical bug is a withdrawal function that sends ETH before zeroing the caller's recorded balance:

```solidity
// VULNERABLE: external call happens before state update
mapping(address => uint256) public balance;

function withdraw() external {
    uint256 amount = balance[msg.sender];
    require(amount > 0, "nothing to withdraw");

    // Interaction BEFORE effect: hands control to msg.sender
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");

    balance[msg.sender] = 0;   // too late: attacker already re-entered
}
```

When `msg.sender` is an attacker contract, the `call` invokes that contract's `receive()`, which calls `withdraw()` again. Because `balance[msg.sender]` is still the original amount, the check passes and another payment is sent—looping until the contract is empty or gas runs out.

### Categories of Reentrancy

#### 1. Single-function (same-function) reentrancy

The attacker re-enters the *same* function that made the external call—the classic `withdraw` loop above. This is the original DAO-class bug.

#### 2. Cross-function reentrancy

The attacker re-enters a *different* function that shares state with the one making the call. For example, `withdraw()` sends ETH before updating `balance`, and during that call the attacker invokes `transfer(friend, balance)`—which reads the not-yet-zeroed balance and moves it elsewhere before `withdraw` resets it.

#### 3. Cross-contract reentrancy

Two or more contracts share state (or one caches another's state). An external call lets the attacker re-enter *Contract A* through *Contract B* while a shared value is mid-update, so B acts on state A has not yet finalised.

#### 4. Read-only reentrancy

Even a `view` function can be dangerous. During a re-entrant callback, a getter (for example, `getPrice()` or `getVirtualPrice()`) returns a value computed from state that is temporarily inconsistent. The attacking transaction calls an *integrating* protocol that reads that getter and makes a decision—pricing collateral, minting shares—on the stale number. Nothing is written in the victim getter, which is exactly why it is easy to miss.

#### 5. Token-hook (ERC777 / ERC721) reentrancy

Some token standards call the recipient during a transfer. ERC777 invokes `tokensReceived` on the recipient; ERC721 `safeTransferFrom` invokes `onERC721Received`. These hooks are legitimate features, but they hand control to the recipient in the middle of a transfer, enabling reentrancy even when no raw ETH is sent. A contract that treats an ERC20-style `transfer` as a "safe, non-reentrant" step can be blindsided when the token is actually ERC777.

#### 6. Delegatecall reentrancy

Proxy and library patterns use `delegatecall`, which runs external code in the caller's own storage context. If the delegated code makes an external call before the proxy's state is settled—or if an upgradeable contract's storage layout can be re-entered mid-operation—an attacker can manipulate the shared storage through re-entry.

### Where the External Call Hides

| Mechanism | How control leaves the contract | Re-entry hook |
|-----------|--------------------------------|---------------|
| ETH via `call{value:}` | Low-level call with gas forwarded | Recipient `receive()` / `fallback()` |
| ETH via `transfer`/`send` | 2300 gas stipend (historically limiting) | Recipient fallback (gas-starved, but not safe to rely on) |
| ERC777 token transfer | Standard-mandated recipient callback | `tokensReceived` hook |
| ERC721 `safeTransferFrom` | Safe-transfer acceptance check | `onERC721Received` hook |
| Arbitrary contract call | Calling any external/untrusted address | Callee runs any code, including re-entry |
| `delegatecall` to library/logic | External code runs in caller's storage | Delegated code re-enters shared storage |

## Real-World Impact

### Incident Class 1: The DAO-Class Reentrancy (2016)

**Pattern**:
- A large investment contract paid out a member's share by sending ETH before it updated that member's recorded balance to zero.
- An attacker contract's fallback re-entered the withdrawal ("split") path repeatedly during a single call, each time seeing the original, undecremented balance.

**Impact**:
- A very large fraction of the contract's funds was drained through recursive re-entry before state was ever finalised.
- The incident was severe enough that the Ethereum community ultimately hard-forked the chain, splitting it into Ethereum and Ethereum Classic—a defining event for the ecosystem.

**Root Cause**: Interactions-before-Effects ordering in the withdrawal path, with no reentrancy guard. It is the archetype from which the whole category takes its name.

### Incident Class 2: Token-Callback Reentrancy (ERC777-style)

**Pattern**:
- A protocol integrated a token that runs a recipient hook (`tokensReceived`) on transfer, but treated the transfer as an ordinary, non-reentrant step.
- During the hook, the attacker re-entered a function that relied on balances or accounting the transfer had not yet finalised.

**Impact**: Protocols that assumed "a token transfer cannot call back" were drained or left with corrupted accounting when the token turned out to hand control to the recipient mid-transfer.

**Root Cause**: An unrecognised external call inside a token transfer, combined with state updated after that transfer. The lesson generalised into: treat every token transfer as a potential external call.

### Incident Class 3: Read-Only Reentrancy in DeFi Integrations

**Pattern**:
- A pool exposed a `view` getter (such as a virtual price or share value) that was temporarily inconsistent while a withdrawal callback was executing.
- An integrating protocol read that getter during the callback and priced collateral or minted shares on the stale value.

**Impact**: Lending markets and other integrators that trusted the getter mid-transaction could be induced to over-value or under-value assets, enabling under-collateralised borrows or unfair mints—without the vulnerable getter itself ever writing state.

**Root Cause**: A getter that returns intermediate state during a reentrant window, trusted by an external consumer. It shows that reentrancy defences must cover *view* functions and cross-protocol reads, not just state-changing withdrawals.

## Prevalence and Significance

Reentrancy is one of the most recognised and studied vulnerability classes in smart-contract security, and it is included as **SC05** in the OWASP Smart Contract Top 10 (2025). Despite being well understood since 2016, it continues to appear—usually in a newer form (cross-function, cross-contract, read-only, or token-hook) rather than the textbook single-function case.

Rather than cite precise loss totals (which vary by source and year), the defensible picture is:

- The **classic single-function pattern** is now widely caught by audits and linters, so surviving bugs tend to be the subtler variants.
- **Read-only reentrancy** emerged as a significant modern class precisely because `view` functions were long assumed to be harmless.
- **Token-hook reentrancy** keeps recurring as protocols integrate tokens (ERC777/ERC721) whose transfers hand control to the recipient.
- The impact is consistently rated **critical**: successful reentrancy typically means direct, irreversible loss of the contract's funds.

> Note: exact loss figures differ between reports. Treat any single number as illustrative; the durable takeaway is that reentrancy remains high-impact and keeps resurfacing in new forms as composability grows.

## Common Misunderstandings

### Myth 1: "Using `transfer`/`send` instead of `call` makes me safe"

**Reality**: The 2300-gas stipend of `transfer`/`send` historically made re-entry hard, but it is *not* a security guarantee—gas costs change, and cross-function or token-hook paths do not depend on that stipend. Modern guidance is to use `call` *with* Checks-Effects-Interactions and a guard, not to rely on gas limits.

### Myth 2: "Only functions that send ETH can be re-entered"

**Reality**: Any external call is a re-entry point. ERC777 `tokensReceived`, ERC721 `onERC721Received`, and any call to an untrusted contract all hand over control—no raw ETH required.

### Myth 3: "`view` functions are harmless"

**Reality**: Read-only reentrancy exploits `view` getters that return inconsistent state mid-transaction. The getter writes nothing, but an integrating protocol acting on its value can be drained.

### Myth 4: "A reentrancy guard on one function is enough"

**Reality**: Cross-function reentrancy re-enters a *different* function that shares state. A guard must cover every function that touches the same state, and getters consumed by others may need protection too.

### Myth 5: "My external call is to a trusted contract, so re-entry can't happen"

**Reality**: "Trusted" contracts can themselves be upgradeable, call untrusted code, or hold tokens with hooks. Treat every external call as potentially reentrant and order your state changes accordingly.

### Myth 6: "Checks-Effects-Interactions and a mutex are redundant—pick one"

**Reality**: They are complementary. CEI removes the incentive to re-enter by finalising state first; a `nonReentrant` mutex is defence-in-depth that also covers cross-function paths and cases where an external call is genuinely unavoidable mid-logic.

## How Reentrancy Differs from Related Issues

| Aspect | Reentrancy (SC05) | Access Control (SC01) | Logic Errors (SC03) |
|--------|-------------------|-----------------------|---------------------|
| **Root cause** | External call before state update | Missing/incorrect authorization | Flawed business rules/math |
| **Trigger** | Re-entry via callee code | Unauthorized caller | Valid caller, wrong outcome |
| **Typical fix** | CEI ordering + reentrancy guard | Proper role/permission checks | Correct and verify invariants |
| **Detection** | Call-then-write pattern analysis | Auth-path review | Spec & invariant testing |

## Key Takeaways

1. **Reentrancy is an ordering bug**—an external call made before state is finalised lets the callee act on stale state.
2. **Any external call is a door**—ETH sends, ERC777/ERC721 hooks, arbitrary calls, and `delegatecall` all pass control to code that may re-enter.
3. **The variants are what bite today**—cross-function, cross-contract, and read-only reentrancy survive audits that only look for the classic loop.
4. **Fix by ordering, then guard**—apply Checks-Effects-Interactions first, add a `nonReentrant` mutex as defence-in-depth.
5. **Losses are final**—a single reentrant transaction can drain the whole balance, and on-chain there is no undo.

## How to Identify if You're Vulnerable

- [ ] Does any function make an external call (ETH send, token transfer, arbitrary call) *before* writing all of its state changes?
- [ ] Do you follow Checks-Effects-Interactions on every function that moves value?
- [ ] Are functions that share state protected by a reentrancy guard (or otherwise safe against cross-function re-entry)?
- [ ] Could any token you handle be ERC777/ERC721 and call the recipient on transfer?
- [ ] Do any `view` getters return state that is inconsistent mid-transaction, and are they trusted by other protocols (read-only reentrancy)?
- [ ] Do you use `delegatecall` to code that makes external calls before your storage is settled?
- [ ] Do you favour pull-over-push withdrawals rather than pushing ETH to many recipients in a loop?
- [ ] Have you assumed `transfer`/`send` gas limits protect you (they do not)?

If you answered "yes" to the call-before-write questions or "not sure" to the guard questions, you likely have exploitable reentrancy today.

## Next Steps

- **[Attack Vectors](attack-vectors.md)**: How attackers trigger and chain reentrancy
- **[Prevention](prevention.md)**: CEI, reentrancy guards, and pull-over-push withdrawals
- **[Examples](examples.md)**: Vulnerable vs. secure Solidity, side by side
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
