# SC02: Price Oracle Manipulation - Prevention

## Prevention Strategy Overview

Preventing oracle manipulation is less about one control and more about **never acting on a price a single transaction can move**:

1. Source prices from robust, decentralized oracles—not raw spot reads.
2. Validate every price for freshness and plausibility before using it.
3. Use time-weighted values that a single block cannot push.
4. Cross-check independent sources and reject disagreement.
5. Assume flash-loaned capital and add circuit breakers for the abnormal case.

### Core Principles

- **Assume unlimited atomic capital**: design as if an attacker can flash-loan any amount for free within one transaction.
- **Prefer manipulation-resistant sources**: decentralized feeds and TWAPs over instantaneous spot reads.
- **Validate, don't trust**: freshness, sign, and deviation checks on every price, every time.
- **Fail closed**: if sources are stale or disagree beyond a bound, pause the price-sensitive path rather than act on a suspect value.

## 1. Use Robust Decentralized Oracles (with checks)

A decentralized price feed (e.g. Chainlink) aggregates many independent off-chain sources, so no single on-chain pool can move it. But the feed must still be **read defensively**: check freshness, sign, and round completeness.

```solidity
// Chainlink read with the checks that actually matter
AggregatorV3Interface internal feed;
uint256 public constant MAX_STALENESS = 1 hours;

function getPrice() public view returns (uint256) {
    (
        uint80 roundId,
        int256 answer,
        ,
        uint256 updatedAt,
        uint80 answeredInRound
    ) = feed.latestRoundData();

    require(answer > 0, "bad price");                       // reject zero/negative
    require(updatedAt != 0, "round not complete");
    require(block.timestamp - updatedAt <= MAX_STALENESS,   // freshness
            "stale price");
    require(answeredInRound >= roundId, "stale round");

    return uint256(answer);
}
```

Never use `latestAnswer()` (it exposes no timestamp), and always confirm the feed exists for the exact asset pair and decimals you assume.

## 2. Use Time-Weighted Average Prices (TWAP)

Where an on-chain source is unavoidable, average it over time so a single-block swing cannot move the value you act on. A TWAP over a meaningful window forces an attacker to sustain the manipulation across many blocks—expensive and highly visible.

```solidity
// Uniswap V3-style TWAP over a window, instead of a spot read
uint32 secondsAgo = 1800;                 // 30-minute window
uint32[] memory ago = new uint32[](2);
ago[0] = secondsAgo; ago[1] = 0;

(int56[] memory tickCumulatives, ) = pool.observe(ago);
int56 delta = tickCumulatives[1] - tickCumulatives[0];
int24 avgTick = int24(delta / int56(uint56(secondsAgo)));
// convert avgTick -> price with the standard tick math (window-averaged, not spot)
```

Choose the window deliberately: too short and it is still pushable; too long and it lags real moves. Pair TWAP with a deviation check against an independent feed.

## 3. Aggregate Multiple Independent Sources

Do not depend on a single venue. Read two or more independent sources and require them to agree within a bound—or take a median—so manipulating one is not enough.

```solidity
// Cross-check a decentralized feed against a TWAP; reject wide disagreement
uint256 constant MAX_DEVIATION_BPS = 200;   // 2%

function safePrice() public view returns (uint256) {
    uint256 feedPrice = getPrice();          // Chainlink (checked)
    uint256 twapPrice = getTwapPrice();      // on-chain TWAP

    uint256 diff = feedPrice > twapPrice ? feedPrice - twapPrice
                                         : twapPrice - feedPrice;
    require(diff * 10_000 / feedPrice <= MAX_DEVIATION_BPS,
            "sources disagree");             // fail closed on divergence
    return feedPrice;
}
```

## 4. Add Deviation and Sanity Bounds

Reject prices that are implausible relative to a recent trusted value. A hard min/max band and a per-update deviation cap stop a single distorted read from being acted on.

```solidity
uint256 public lastGoodPrice;
uint256 constant MAX_MOVE_BPS = 1000;        // 10% per update

function boundedPrice(uint256 candidate) internal view returns (uint256) {
    require(candidate >= PRICE_FLOOR && candidate <= PRICE_CEIL, "out of range");
    uint256 move = candidate > lastGoodPrice ? candidate - lastGoodPrice
                                             : lastGoodPrice - candidate;
    require(move * 10_000 / lastGoodPrice <= MAX_MOVE_BPS, "implausible jump");
    return candidate;
}
```

## 5. Avoid Spot Prices and Manipulable Balances

Treat these as **never** acceptable as a price oracle:

- `getReserves()` and other instantaneous reserve reads.
- `getAmountsOut()` / router swap quotes.
- `token.balanceOf(pool)` or raw pool balances as a value proxy.
- Naive LP-token valuations from live reserves.

```solidity
// DO NOT: spot price straight from reserves
(uint112 r0, uint112 r1, ) = pair.getReserves();
uint price = uint(r1) * 1e18 / uint(r0);      // flash-loan movable

// DO: read a checked decentralized feed / TWAP instead (sections 1-2)
```

For LP tokens, use a **manipulation-resistant fair-value** formula that prices the underlying from trusted feeds and derives the reserves from the invariant (a "fair reserves" calculation), rather than reading the live, movable balances.

## 6. Circuit Breakers and Bounds on Actions

Even with good prices, cap the blast radius. A guardian pause, per-block or per-tx borrow/mint limits, and a freeze when sources disagree turn a total loss into a bounded, recoverable event.

```solidity
modifier priceHealthy() {
    require(!paused, "protocol paused");
    require(oracleSourcesAgree(), "oracle divergence - halted");
    _;
}

function borrow(uint256 amount) external priceHealthy {
    require(amount <= maxBorrowPerBlock, "rate limit");   // cap the damage
    // ... pricing uses safePrice() with all checks ...
}
```

## 7. Model Flash-Loan Atomicity in the Threat Model

Assume every price-sensitive path can be entered by an attacker who, in the same transaction, controls arbitrary capital and can move any pool you read. Concretely:

- For each price read, ask: "If an attacker could set this value freely for one transaction, what could they extract?"
- Do not rely on "no one has enough capital"—flash loans remove that assumption.
- Where feasible, prevent an action from both moving a price and consuming it within the same transaction (time-averaging inherently helps here).

## 8. Use Manipulation-Resistant Liquidity

The cost of manipulation scales with the depth and breadth of the sources you price from.

- Price from **deep, high-liquidity** pools and feeds; never from a thin pool an attacker can move cheaply.
- Prefer sources that aggregate across many venues, so no single pool is decisive.
- When onboarding a new collateral asset, evaluate how cheaply its price can be moved *before* accepting it.

## 9. Testing and Verification

Prove the pricing path survives a manipulation attempt—don't assume it.

```bash
# Fork-test the exact pricing path under a simulated flash-loan swing
forge test --fork-url $RPC --match-test testFlashLoanManipulation -vvvv

# In the test: flash-loan, skew the pool, call the victim function,
# and assert the protocol does NOT over-lend / mis-mint / mis-liquidate.
```

Also add invariant/fuzz tests asserting that no sequence of swaps within one transaction lets a caller extract more value than they deposited, and have the oracle logic independently audited.

## 10. Monitoring and Detection

Watch for the on-chain signatures of manipulation and feed failure.

```
# Alert conditions (off-chain monitors on your contracts/feeds):
- Oracle price deviates > N% from an independent reference
- Feed updatedAt exceeds MAX_STALENESS (feed frozen)
- Large single-tx swaps in pools your protocol prices from
- Borrow/mint/liquidation immediately preceded by a big swap in the same tx
- Circuit breaker / pause triggered
```

Route these to an on-call path with the ability to pause price-sensitive functions quickly.

## Defense Summary

| Weak pattern | Robust replacement |
| --- | --- |
| Spot reserves / `getAmountsOut` | Decentralized feed and/or TWAP |
| Single source, believed blindly | Multiple independent sources, median / deviation-checked |
| `balanceOf` / naive LP value | Fair-value from trusted feeds + invariant |
| Feed read with no checks | Freshness, sign, and round-completeness checks |
| Unbounded action on any price | Deviation bounds + circuit breakers + rate limits |

## Key Takeaways

1. **Never act on a spot price** — reserves, quotes, and balances all move in one transaction.
2. **Prefer robust feeds and TWAPs** — and still validate freshness, sign, and completeness.
3. **Cross-check and bound** — multiple sources, deviation limits, and sanity ranges catch the abnormal read.
4. **Design for flash loans** — assume unlimited atomic capital in every threat model.
5. **Cap the blast radius** — circuit breakers, pauses, and rate limits turn a drain into a bounded event.

## Next Steps

- **[Code Examples](examples.md)**: Vulnerable spot-price oracles vs. secure Chainlink/TWAP code
- **[Attack Vectors](attack-vectors.md)**: Understand exactly what you're defending against
- **[Smart Contract Top 10](/learn/smart-contract)**: Return to the full lesson index
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
