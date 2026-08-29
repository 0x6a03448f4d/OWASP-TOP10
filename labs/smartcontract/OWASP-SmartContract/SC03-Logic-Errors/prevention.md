# SC03: Logic Errors - Prevention

## Prevention Strategy Overview

Preventing logic errors is less about a single control and more about **making correctness something you state, test, and prove—rather than something you hope for**:

1. Write the specification and its invariants down before writing the code.
2. Handle every edge case explicitly—first depositor, empty pool, zero, boundaries.
3. Decide and enforce rounding direction: always in the protocol's favour.
4. Test the invariants with property-based and fuzz testing, not just examples.
5. Formally verify the critical math and commission multiple independent audits.

### Core Principles

- **Specify before you build**: an invariant you never wrote down is one no reviewer, tool, or auditor can check.
- **Round in the protocol's favour**: on integer arithmetic, the direction of truncation is a security decision.
- **Prefer boring, audited math**: reuse standard libraries and standards rather than hand-rolling formulas.
- **Test the space, not the point**: fuzzing and property tests explore the inputs your examples missed.
- **Keep logic simple and documented**: complexity is where the intended and implemented behaviour drift apart.

## 1. Specify Invariants Explicitly

State, in plain language and then in assertions, the relationships that must always hold. These become the oracle every test checks against.

```solidity
// Intended invariants for a share-based vault:
//   I1: sum of all shareholder shares == totalSupply
//   I2: totalAssets held >= value owed to all shareholders   (never insolvent)
//   I3: a deposit then immediate withdraw never returns MORE than deposited
//   I4: no user can mint shares without transferring the matching assets
//   I5: rounding on mint favours the vault; rounding on redeem favours the vault

// Encode each as an assertion the test suite can enforce:
assert(totalShares() == sumOfBalances());
assert(totalAssets() >= convertToAssets(totalShares()));
```

If you cannot write the invariant, you do not yet understand the contract well enough to ship it.

## 2. Handle Edge Cases Deliberately

The first depositor, the empty pool, the zero amount, and the exact boundary are where value leaks. Address each on purpose.

```solidity
// First-deposit / inflation defence: virtual shares + offset (ERC-4626 style).
// OpenZeppelin's ERC4626 adds a decimals offset so the empty-pool exchange
// rate cannot be cheaply manipulated by a direct donation.
function _decimalsOffset() internal view virtual returns (uint8) {
    return 6;   // virtual shares/assets blunt the first-depositor attack
}

// Reject the degenerate inputs outright where they make no sense:
function deposit(uint256 amount) external {
    require(amount > 0, "zero amount");
    // ... and, for the very first deposit, require a sane minimum or seed the
    // vault at deployment so totalSupply is never manipulable-from-zero.
}
```

## 3. Control Rounding Direction

Make every division state which way it rounds, and always choose the direction that cannot leak value to the caller.

```solidity
// Round DOWN when minting shares (user gets no more than fair):
uint256 shares = amount.mulDiv(totalSupply, totalAssets, Math.Rounding.Floor);

// Round UP when computing what a user must PAY or what shares to BURN
// on withdrawal (protocol never short-changed):
uint256 shares = assets.mulDiv(totalSupply, totalAssets, Math.Rounding.Ceil);

// Use a library with explicit rounding (OpenZeppelin Math.mulDiv) rather than
// bare `a * b / c`, so the direction is a documented decision, not an accident.
```

Rule of thumb: when in doubt, the *protocol* should keep the dust, never the user.

## 4. Verify Actual Amounts (Balance-Delta Accounting)

Never trust the requested amount. Credit only what the contract actually received.

```solidity
// Measure the real delta so fee-on-transfer / rebasing tokens cannot lie to you:
function deposit(uint256 amount) external {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before;   // the truth
    require(received > 0, "no tokens received");
    balances[msg.sender] += received;      // credit what actually arrived
}
// Alternatively, explicitly DISALLOW non-standard tokens with a documented
// allow-list, so the assumption is enforced rather than merely hoped.
```

## 5. Advance Checkpoints in Reward Math

Every accrual must move its checkpoint so no period is ever paid twice.

```solidity
mapping(address => uint256) public lastAccrued;

function _accrue(address user) internal {
    uint256 elapsed = block.timestamp - lastAccrued[user];
    if (elapsed > 0 && stake[user] > 0) {
        rewards[user] += stake[user] * rate * elapsed / PRECISION;
    }
    lastAccrued[user] = block.timestamp;   // MUST advance, every time
}

// Call _accrue() before any action that changes stake, and settle before
// paying out. Invariant to test: total paid <= total emitted.
```

## 6. Use Audited Libraries and Standards

Reuse code that has already survived adversarial scrutiny instead of re-deriving it.

```solidity
// Prefer battle-tested building blocks:
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";
import {Math}    from "@openzeppelin/contracts/utils/math/Math.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

// OpenZeppelin's ERC4626 implements the standard's rounding rules and supports
// a virtual-shares offset for the inflation attack. Extend it rather than
// re-implementing share math from scratch.
```

Solidity 0.8+ reverts on overflow by default, so `SafeMath` is no longer required—but safe arithmetic is not the same as *correct* arithmetic.

## 7. Property-Based and Fuzz Testing

Assert your invariants against thousands of random and adversarial inputs.

```solidity
// Foundry invariant test: the vault must never become insolvent, whatever
// sequence of deposits/withdrawals the fuzzer throws at it.
function invariant_neverInsolvent() public view {
    assertGe(vault.totalAssets(), vault.convertToAssets(vault.totalSupply()));
}

// Foundry property test with random inputs:
function testFuzz_depositThenWithdraw(uint256 amount) public {
    amount = bound(amount, 1, 1e24);
    uint256 shares = vault.deposit(amount, address(this));
    uint256 out    = vault.redeem(shares, address(this), address(this));
    assertLe(out, amount);   // never get back MORE than deposited
}
```

```bash
# Echidna: property-based fuzzing driven by a config, hunting invariant breaks
echidna test/VaultInvariants.sol --contract VaultInvariants --config echidna.yaml
```

Fuzzing finds the zero-amount, first-depositor, and rounding cases that hand-written examples routinely miss.

## 8. Formal Verification for Critical Math

For the core accounting, prove the property holds for *all* inputs rather than sampling.

```solidity
// Formal-verification tools (e.g. Certora, Halmos, the SMTChecker) can prove
// statements like:
//   "for all deposit sequences, sum(shares) == totalSupply"
//   "no reachable state has totalAssets < liabilities"

// Solidity's built-in SMTChecker can be enabled for targeted checks:
pragma experimental SMTChecker;
// then assert the invariant inside the function and let the solver try to
// find a counter-example.
```

Reserve formal methods for the highest-value math (share/mint formulas, interest accrual); the effort is justified where a single error is catastrophic.

## 9. Checks-Effects-Interactions and Correct Ordering

Validate first, update state second, and only then interact with the outside world.

```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");  // checks
    balances[msg.sender] -= amount;                           // effects
    token.safeTransfer(msg.sender, amount);                   // interactions
}
// Correct ordering keeps the state machine in states your invariants cover,
// and (as a bonus) removes the reentrancy window as well.
```

## 10. Keep Logic Simple and Documented

- Prefer the simplest formula that meets the requirement; complexity is where intent and implementation diverge.
- Document, next to the code, the intended behaviour and rounding direction of every non-trivial calculation.
- Commission **multiple independent audits**—different reviewers catch different logic gaps—and give auditors the written specification so they can check against intent, not guess it.
- Run a bug-bounty and a staged/guarded launch (caps, timelocks, pausability) so a residual logic error is bounded rather than fatal.

## Defence Summary

| Logic-Error Class | Primary Defence |
|-------------------|-----------------|
| First-depositor / inflation | Virtual shares/offset, minimum or seeded initial deposit |
| Rounding / precision leakage | Explicit rounding direction, always in the protocol's favour |
| Reward double-count / mis-scale | Advance checkpoints; test `paid <= emitted` |
| Accounting mismatch | Balance-delta accounting; verify what was received |
| Fee-on-transfer / rebasing | Measure real delta or reject non-standard tokens |
| Off-by-one / boundary | Test exact-boundary inputs; review comparison operators |
| Broken invariants generally | Property/fuzz testing + formal verification + audits |

## Key Takeaways

1. **Write the invariants down first** — correctness is a property you specify, then prove; it is not implied by compilation.
2. **Round in the protocol's favour, always** — integer truncation direction is a security decision.
3. **Trust the delta, not the request** — credit only what was actually received.
4. **Fuzz and formally verify the math** — property tests and solvers find the edge cases examples miss.
5. **Reuse audited standards and audit repeatedly** — boring, proven math and multiple reviewers beat clever, unreviewed formulas.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable vs. secure Solidity side by side
- **[Attack Vectors](attack-vectors.md)**: Understand what you're defending against
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
