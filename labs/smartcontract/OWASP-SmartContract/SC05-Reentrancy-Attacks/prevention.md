# SC05: Reentrancy Attacks - Prevention

## Prevention Strategy Overview

Preventing reentrancy is about **never letting an external call observe unfinished state**:

1. Order every function as Checks-Effects-Interactions.
2. Add a reentrancy guard as defence-in-depth, covering functions that share state.
3. Prefer pull-over-push so you rarely send value inside complex logic.
4. Treat every token transfer and external call as potentially reentrant (ERC777/ERC721 hooks, arbitrary calls, `delegatecall`).
5. Protect `view` getters that others rely on against read-only reentrancy.

### Core Principles

- **State first, call last**: finalise all bookkeeping before any external interaction, so re-entry sees the settled world.
- **Defence-in-depth**: CEI removes the incentive to re-enter; a mutex blocks it anyway, including cross-function paths.
- **Least external contact**: fewer and smaller external calls mean fewer re-entry doors; pull-over-push moves the call to a dedicated, isolated function.
- **Assume the callee is hostile**: any address you call may be an attacker contract, an upgradeable proxy, or a token with hooks.

## 1. Checks-Effects-Interactions (the primary fix)

Reorder so state is written **before** the external call. This alone defeats the classic single-function attack.

```solidity
// SECURE: Effects before Interactions
mapping(address => uint256) public balance;

function withdraw() external {
    // 1. Checks
    uint256 amount = balance[msg.sender];
    require(amount > 0, "nothing to withdraw");

    // 2. Effects  (state finalised BEFORE any external call)
    balance[msg.sender] = 0;

    // 3. Interactions
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}
```

When the attacker re-enters `withdraw()` during the `call`, `balance[msg.sender]` is already `0`, so the `require` fails and the loop dies immediately.

## 2. Reentrancy Guard (mutex) as defence-in-depth

A guard sets a lock on entry and clears it on exit, so any re-entrant call reverts. Use OpenZeppelin's audited `ReentrancyGuard` rather than rolling your own.

```solidity
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Vault is ReentrancyGuard {
    mapping(address => uint256) public balance;

    function withdraw() external nonReentrant {   // locks for the whole call
        uint256 amount = balance[msg.sender];
        require(amount > 0);
        balance[msg.sender] = 0;                   // still keep CEI ordering
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
    }
}
```

A minimal illustration of the same idea (do not ship a hand-rolled version—prefer the library):

```solidity
uint256 private _status = 1;   // 1 = unlocked, 2 = locked

modifier nonReentrant() {
    require(_status == 1, "reentrant call");
    _status = 2;
    _;
    _status = 1;
}
```

> Apply `nonReentrant` to *every* function that shares state, not just the one that sends value—otherwise cross-function reentrancy re-enters an unguarded sibling.

## 3. Pull-over-Push Withdrawals

Do not push ETH inside business logic or in a loop. Record what is owed, and let each recipient pull it in an isolated, guarded function.

```solidity
mapping(address => uint256) public pendingWithdrawals;

// Push phase: only bookkeeping, no external call
function endAuction() external {
    pendingWithdrawals[previousBidder] += refundAmount;
    // ... rest of logic, no ETH sent here
}

// Pull phase: isolated, CEI-ordered, guarded
function withdrawRefund() external nonReentrant {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0);
    pendingWithdrawals[msg.sender] = 0;            // effect first
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}
```

This confines the only external call to one small function, shrinks the re-entry surface, and prevents one failing/malicious recipient from blocking everyone else.

## 4. Beware Token Hooks (ERC777 / ERC721)

Token transfers are external calls when the standard defines a recipient hook. Order state updates before such transfers, and guard the function.

```solidity
function claim() external nonReentrant {
    uint256 amt = owed[msg.sender];
    require(amt > 0);
    owed[msg.sender] = 0;                    // effect BEFORE the transfer
    token.safeTransfer(msg.sender, amt);     // ERC777 tokensReceived is now harmless
}
```

- Assume any ERC20 you integrate could be ERC777 (a superset that adds hooks).
- For NFTs, remember `safeTransferFrom`/`safeMint` invoke `onERC721Received`—update "claimed/minted" flags first.
- Follow CEI even for token paths; do not assume "a transfer can't call back."

## 5. Guard Against Read-Only Reentrancy

A `view` getter can return inconsistent values during a reentrant callback. Protect getters that other protocols trust, or expose reentrancy-safe reads.

```solidity
// Option A: a view-side guard that reverts if called during a locked operation
function getVirtualPrice() external view returns (uint256) {
    require(_status == 1, "reentrant read");   // same mutex the state fns use
    return _computeVirtualPrice();
}

// Option B: only read such getters from contexts you control, and/or use a
// value that cannot be mid-update (e.g., checkpoints taken outside callbacks).
```

- If you *integrate* another protocol, do not read its price/share getters inside a callback you did not initiate; prefer values that are settled.
- If you *expose* such a getter, ensure it cannot be observed while your own state is temporarily inconsistent.

## 6. Minimise and Isolate External Calls

- Make the fewest external calls possible, and make them last.
- Never call an untrusted address in the middle of a multi-step state change.
- In proxy/`delegatecall` designs, ensure delegated logic cannot make an external call before shared storage is settled.
- Do not rely on `transfer`/`send` gas stipends as a safety mechanism—use `call` plus CEI plus a guard.

## 7. Testing, Tooling, and Review

Reentrancy is highly detectable with the right tooling. Make it part of CI.

```bash
# Static analysis: flags call-before-write and reentrancy patterns
slither .                       # includes reentrancy-eth / reentrancy-no-eth detectors

# Symbolic / property analysis
mythril analyze Contract.sol    # explores reentrant execution paths

# Fuzzing / invariant testing (write a malicious re-entering contract as the harness)
forge test                       # Foundry: assert "total paid out <= total deposited"
echidna Contract.sol             # property-based fuzzing of invariants
```

Write an explicit attacker contract in your test suite whose `receive()`/hook re-enters the target, and assert the invariant (for example, "the contract can never pay out more than was deposited") holds.

## Defence Summary

| Control | Stops | Notes |
|---------|-------|-------|
| Checks-Effects-Interactions | Single-function reentrancy | Primary fix; state finalised before the call |
| `nonReentrant` mutex | Single- & cross-function reentrancy | Apply to all functions sharing state |
| Pull-over-push | Loop-based & push reentrancy | Confines the external call to one function |
| Hook-aware ordering | ERC777/ERC721 reentrancy | Update state before hooked transfers |
| View-side guard / safe reads | Read-only reentrancy | Protect getters integrators trust |
| Static analysis in CI | Regressions | Slither/Mythril catch call-then-write |

## Key Takeaways

1. **CEI first** — write all state before any external call; this alone defeats the classic drain.
2. **Guard everything that shares state** — a mutex on one function misses cross-function re-entry.
3. **Pull, don't push** — isolate value transfers in one small, guarded function.
4. **Every transfer is a call** — ERC777/ERC721 hooks and arbitrary calls can all re-enter.
5. **Don't forget getters** — read-only reentrancy needs view-side protection or settled reads.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Solidity, side by side
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
