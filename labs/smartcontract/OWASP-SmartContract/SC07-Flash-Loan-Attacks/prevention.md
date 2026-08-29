# SC07: Flash Loan Attacks - Prevention

## Prevention Strategy Overview

You cannot reliably stop attackers from taking flash loans, and trying to is the wrong target. The durable defence is to **make your protocol indifferent to how much capital any actor holds for one transaction**:

1. Design every mechanism assuming an attacker has effectively unlimited capital for a single transaction.
2. Never trust a value that can be moved within one block—spot prices, live balances, instantaneous share ratios.
3. Use time-resistant sources: TWAP / robust oracles for prices, past-block snapshots for votes.
4. Add reentrancy guards, CEI ordering, deviation bounds, and circuit breakers.
5. Assume attempts are free and constant—so any gap will be found.

### Core Principles

- **Assume infinite one-tx capital**: if a mechanism only holds because "no one can afford to move it," it is already broken.
- **Distrust single-block snapshots**: a price or balance read this block can be an attacker's lie.
- **Prefer manipulation-resistant sources**: averages over time and balances from the past cannot be flash-inflated.
- **Fail safe on anomalies**: bound deviations and halt on impossible swings rather than transacting through them.

## 1. Never Trust Spot Price — Use TWAP / Robust Oracles

The single most important defence. A spot price read from one pool's current reserves is trivially skewed by a flash swap. A time-weighted average price (TWAP) forces an attacker to hold the manipulation across many blocks—which a flash loan cannot do—and a robust oracle aggregates multiple independent sources. (See **SC02** for full oracle design.)

```
// VULNERABLE: instantaneous spot price
function getPrice() external view returns (uint) {
    return pool.reserveQuote() * 1e18 / pool.reserveBase();  // one flash swap moves this
}

// HARDENED: time-weighted average, immune to single-tx skew
function getTwapPrice(uint32 window) external view returns (uint) {
    // sample the pool's cumulative price at now and (now - window),
    // divide the delta by the window -> average price over `window` seconds.
    // A flash loan cannot move an average sustained across many blocks.
    return _consultTwap(window);   // e.g. 30-minute window
}

// BEST: cross-check an aggregated feed against the TWAP and reject on divergence.
```

## 2. Governance: Snapshot Balances from a Past Block + Timelocks

Voting power must be read from a **checkpoint at a block in the past** (the proposal's snapshot block), not from the live balance. A flash borrower holds tokens only in the current transaction, so a past-block snapshot gives them zero weight. A **timelock** on execution further guarantees a proposal cannot be voted and executed in the same transaction.

```
// VULNERABLE: live balance can be flash-inflated
uint weight = govToken.balanceOf(msg.sender);

// HARDENED: weight from a snapshot taken when the proposal was created
uint weight = govToken.getPastVotes(msg.sender, proposal.snapshotBlock);
//            ^ ERC20Votes-style checkpoint from a PAST block -> flash balance = 0

// AND separate voting from execution with a delay:
//   propose() -> snapshot taken
//   vote()    -> weighted by past-block balances only
//   queue()   -> enters timelock (e.g. 48h)
//   execute() -> only after the delay, in a LATER transaction
```

## 3. Reentrancy Guards and Checks-Effects-Interactions

Flash capital multiplies what a reentrancy bug can steal. Update internal state *before* any external call, and add a guard so a function cannot be re-entered. (See **SC05**.)

```
// HARDENED withdrawal: effects before interactions + nonReentrant
mapping(address => uint) balances;
bool private locked;

modifier nonReentrant() {
    require(!locked, "reentrant");
    locked = true;
    _;
    locked = false;
}

function withdraw(uint amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "insufficient");
    balances[msg.sender] -= amount;                 // EFFECT first
    (bool ok, ) = msg.sender.call{value: amount}(""); // INTERACTION last
    require(ok, "transfer failed");
}
```

## 4. Avoid Logic That Large Atomic Swaps Can Game

Any formula that scales with a manipulable balance or ratio must be stress-tested at extreme inputs. Common hardening: initialise pools with a minimum liquidity / dead shares to defeat first-depositor inflation, round in the protocol's favour, and never derive value from an instantaneous, attacker-supplied balance.

```
// Defuse first-depositor share inflation by seeding dead shares at init:
uint constant MINIMUM_LIQUIDITY = 1e3;
function initialize() internal {
    _mint(address(0xdead), MINIMUM_LIQUIDITY);   // shares that can never be redeemed
}

// Round shares DOWN on mint and assets DOWN on withdraw so dust never favours caller.
// Derive share price from tracked internal accounting, not from token.balanceOf(this).
```

## 5. Deviation Bounds and Sanity Checks

Reject prices and state transitions that move more than a plausible amount in a single update. An impossible swing is almost always manipulation.

```
// Reject a new price that deviates too far from the trusted reference:
function requireSanePrice(uint newPrice, uint referencePrice) internal pure {
    uint maxDeviationBps = 200; // 2%
    uint diff = newPrice > referencePrice ? newPrice - referencePrice
                                          : referencePrice - newPrice;
    require(diff * 10_000 / referencePrice <= maxDeviationBps, "price deviation too large");
}
```

## 6. Circuit Breakers and Per-Block Action Limits

Cap the value that can move through sensitive paths, and allow a guardian (or automated trigger) to pause on anomaly. Rate-limiting per block blunts single-transaction drains even if another control fails.

```
// Pausable + per-block outflow cap
bool public paused;
uint public constant MAX_OUTFLOW_PER_BLOCK = 1_000_000e18;
mapping(uint => uint) outflowInBlock;

modifier whenNotPaused() { require(!paused, "paused"); _; }

function _accountOutflow(uint amount) internal {
    outflowInBlock[block.number] += amount;
    require(outflowInBlock[block.number] <= MAX_OUTFLOW_PER_BLOCK, "block outflow cap");
}
```

## 7. Break Single-Transaction Composability Where It Matters

For the most sensitive actions, require that deposit and a value-bearing action do not both settle in the same transaction/block. A minimum holding period or a commit–reveal step means an attacker cannot borrow, act, and repay atomically.

```
// Enforce a minimum holding period before a deposit can be used to withdraw/vote:
mapping(address => uint) firstDepositBlock;

function deposit(uint amount) external {
    if (firstDepositBlock[msg.sender] == 0) firstDepositBlock[msg.sender] = block.number;
    // ... credit deposit ...
}

function actOnDeposit() external {
    require(block.number > firstDepositBlock[msg.sender], "same-block action blocked");
    // ... value-bearing action ...
}
```

## 8. Testing and Monitoring

- **Write flash-loan tests**: fork mainnet, take a real flash loan in a test, and attempt to break each mechanism with attacker-scale capital before shipping.
- **Fuzz and invariant-test**: assert protocol invariants (solvency, share-price monotonicity) hold under extreme, adversarial inputs.
- **Monitor on-chain**: alert on abnormal price deviations, large single-block flows, and governance actions with unusual vote sources.

```
// Foundry-style sketch: prove a mechanism survives attacker-scale capital.
function test_cannotDrainWithFlashCapital() public {
    uint huge = 100_000_000e18;
    deal(address(token), address(attacker), huge);   // simulate flash capital
    vm.expectRevert();                               // manipulation must NOT profit
    attacker.attack(huge);
    assertEq(vault.totalAssets(), initialAssets);    // invariant: reserves intact
}
```

## Defence-to-Weakness Mapping

| Amplified Weakness | Primary Defence | Related Category |
| --- | --- | --- |
| Spot-price oracle skew | TWAP / aggregated robust oracle + deviation bounds | SC02 |
| Balance-based voting | Past-block snapshot balances + execution timelock | Governance |
| Share / accounting error | Dead shares, round-in-protocol-favour, internal accounting | SC03 |
| Reentrancy drain | CEI ordering + `nonReentrant` guard | SC05 |
| Liquidation gaming | Manipulation-resistant price for health checks | SC02 |
| Single-tx atomic drain | Circuit breakers, per-block caps, holding periods | SC07 |

## Key Takeaways

1. **Don't fight the loan, fix the trust** — make the protocol indifferent to any actor's momentary capital.
2. **TWAP and robust oracles** — never price off a single-block spot value.
3. **Snapshot votes from the past + timelock** — a flash-borrowed balance must count for zero.
4. **Guards, bounds, and breakers** — CEI, reentrancy guards, deviation checks, and per-block caps catch what slips through.
5. **Test at attacker scale** — assume unlimited one-tx capital in every test, because attackers will.

## Next Steps

- **Code Examples**: Vulnerable vs. secure Solidity, side by side
- **Attack Vectors**: Understand exactly what you're defending against
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
