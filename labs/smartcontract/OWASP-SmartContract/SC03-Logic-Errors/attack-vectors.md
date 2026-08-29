# SC03: Logic Errors - Attack Vectors

## Table of Contents
- [Understanding Logic-Error Attack Vectors](#understanding-logic-error-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Logic Errors](#chaining-logic-errors)

## Understanding Logic-Error Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Logic errors are not exploited with a clever memory trick or a malformed call. They are exploited with **arithmetic**: an attacker reads the verified source, models the intended invariant, finds the input where the implementation disagrees with the intent, and executes exactly the ordinary transactions that push value in their direction. The contract does precisely what its code says—which is the problem.

The attacker's goal in this category is usually one of:

- Mint *too many* shares/tokens for the assets contributed (or make a victim mint too few).
- Withdraw *more* value than was deposited by exploiting a mis-tracked balance.
- Extract rewards or emissions beyond the intended schedule.
- Bypass a cap, window, or limit via an off-by-one or wrong comparison.

### Core Attack Flow

```
1. Read
   |
   Study verified source; write down the INTENDED invariant
2. Model
   |
   Find the input where implemented math diverges (edge case, rounding, order)
3. Position
   |
   Set up state: be first depositor, seed a stake, or size an amount precisely
4. Execute / Extract
   |
   Send ordinary calls that leave you with more value than you put in
```

## Common Attack Patterns

### 1. First-Depositor Share Inflation (Donation Attack)

The canonical vault logic error. The attacker becomes the first depositor, then donates directly to inflate the share price so a victim rounds down to zero shares.

```solidity
// Vulnerable vault: shares = amount * totalSupply / totalAssets, 1:1 when empty
// Step 1: attacker deposits 1 wei  -> mints 1 share (totalSupply = 1)
vault.deposit(1);

// Step 2: attacker transfers 10,000e18 tokens DIRECTLY to the vault
token.transfer(address(vault), 10_000e18);   // not via deposit(): no shares minted
// Now: totalSupply = 1 share, totalAssets ~= 10,000e18

// Step 3: victim deposits 5,000e18
//   shares = 5,000e18 * 1 / 10,000e18 = 0   (integer truncation)
vault.deposit(5_000e18);                      // victim mints ZERO shares

// Step 4: attacker redeems the single share, now backed by ~15,000e18
vault.redeem(1);                              // walks away with victim's deposit
```

**Payoff**: the victim's assets are absorbed by the attacker's share. Mitigated by virtual shares/offset, a minimum initial deposit, or seeding the vault at deployment.

### 2. Rounding / Truncation Value Leakage

The attacker sizes amounts so integer division truncates in their favour, repeatedly.

```solidity
// If shares burned round DOWN but assets returned round in the caller's favour,
// each round-trip can leak a sliver. Sized and looped, the slivers add up.
for (uint i = 0; i < N; i++) {
    uint256 shares = vault.deposit(craftedAmount);  // rounds to attacker benefit
    vault.redeem(shares);                            // returns >= deposited
}
// Net: attacker ends with more assets than they started; pool loses the delta.
```

**Payoff**: continuous drain of pooled value. Watch for any place where deposit and withdraw round in *different* directions, or where a fee is computed with truncation the user controls.

### 3. Reward Double-Counting

The attacker exploits a reward formula that never advances its checkpoint.

```solidity
// claim() computes owed from elapsed time but forgets to update lastClaim:
stakingPool.stake(amount);
// ... time passes ...
stakingPool.claim();   // pays for elapsed period
stakingPool.claim();   // pays for the SAME period again (checkpoint not moved)
stakingPool.claim();   // ... and again
```

**Payoff**: the attacker mints or receives the same accrual repeatedly, draining the reward pool and diluting holders. A mis-scaled fixed-point rate produces the same effect in a single call.

### 4. Accounting Mismatch / Over-Withdrawal

The attacker finds a path where the recorded balance grows faster than the value actually contributed.

```solidity
// deposit() credits before verifying the real transfer, or ignores the return:
token.approve(address(pool), amount);
pool.deposit(amount);          // balances[attacker] += amount, unconditionally
// If the transfer moved fewer tokens (or none) than credited, the ledger lies.
pool.withdraw(amount);         // withdraw against the inflated recorded balance
```

**Payoff**: withdraw more than was ever deposited; the last users to exit find the pool short.

### 5. Fee-on-Transfer / Rebasing Token Confusion

The attacker supplies a non-standard token to a contract that assumes amount-in equals amount-received.

```solidity
// Contract credits the REQUESTED amount, but a fee-on-transfer token
// delivered less. The gap is now recorded as if it were real backing.
// deposit(1000) with a 10% fee token -> contract holds 900, credits 1000.
// Attacker withdraws 1000 elsewhere, draining 100 of other users' funds.
```

**Payoff**: the recorded/real gap is siphoned. Rebasing tokens cause the mirror problem—balances shift after accounting is recorded.

### 6. Off-by-One / Boundary Bypass

The attacker slips one unit past a cap or window because of a wrong comparison.

```solidity
// require(minted + qty < MAX);  // strict < leaves one slot; <= would fill exactly
mint(MAX - minted);              // exploit whichever direction the operator is wrong
// Or a window guarded by > instead of >= lets an action land one second too late/early.
```

**Payoff**: exceed a supply cap, act outside an intended time window, or claim one increment that should have been denied.

### 7. State-Transition Manipulation

The attacker drives the contract into a combination of states the author assumed impossible.

```solidity
// A flag set out of order, or an effect applied before its guard, lets the
// attacker call a function while the contract is in a state it never validated:
auction.settle();     // settles
auction.bid();        // logic assumed bidding was closed after settle, but the
                      // state flag was updated in the wrong order
```

**Payoff**: actions execute in a context the invariants did not cover, corrupting balances or ownership.

### 8. Price / Share-Rate Manipulation via Composition

The attacker uses flash loans to momentarily distort a quantity the contract's math depends on.

```solidity
// If share value or a fee is derived from a manipulable on-chain quantity
// (e.g. raw balanceOf of a pool), a flash loan can skew it for one transaction:
flashLoan(bigAmount);
//   distort the pool balance -> contract's math now misprices shares/assets
//   mint or redeem at the wrong rate
repayFlashLoan();
```

**Payoff**: mint or redeem at an artificial rate within a single atomic transaction. (Overlaps with oracle/price issues, but the root defect here is math that trusts a manipulable input.)

## Chaining Logic Errors

Individually small discrepancies combine into full compromise:

```
Empty-pool 1:1 share rule      -> attacker becomes first depositor
        +
Direct donation inflates rate  -> victim deposit rounds to zero shares
        +
Truncation favours the holder  -> redemption returns more than fair
        =  attacker redeems one share for the victim's entire deposit
```

Another common chain:

```
Reward checkpoint never advances -> claim the same period repeatedly
        -> re-stake the inflated rewards for a larger base
        -> off-by-one cap check lets the stake exceed the intended maximum
        =  emissions drained far beyond schedule
```

## Key Takeaways

1. **Logic errors are exploited by arithmetic, not payloads**—the attacker out-models the developer and lets the code do the rest.
2. **Edge cases are the entry point**—first depositor, empty pool, zero amount, and boundaries are probed first.
3. **Rounding is a weapon**—truncation that favours the caller is a repeatable drain.
4. **Checkpoints and accounting must be exact**—a period paid twice or a balance credited without verification is money lost.
5. **Small discrepancies chain**—an empty-pool rule plus a donation plus a rounding bias equals a full drain with no exploit primitive at all.

## Next Steps

- **[Prevention Guide](prevention.md)**: Specify invariants, test them, and round in the protocol's favour
- **[Code Examples](examples.md)**: See vulnerable vs. secure Solidity side by side
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
