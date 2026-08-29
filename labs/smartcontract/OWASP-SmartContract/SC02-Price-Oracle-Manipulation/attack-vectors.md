# SC02: Price Oracle Manipulation - Attack Vectors

## Table of Contents
- [Understanding Oracle Manipulation Attack Vectors](#understanding-oracle-manipulation-attack-vectors)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining and Amplifying the Manipulation](#chaining-and-amplifying-the-manipulation)

## Understanding Oracle Manipulation Attack Vectors

> **⚠️ EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Oracle manipulation is not exploited through a clever payload or a compiler quirk. It is exploited through **market mechanics**: the attacker changes the state of a price source the victim contract trusts, then calls the victim while it is reading the distorted value. Because DeFi transactions are atomic and flash loans supply effectively unlimited short-term capital, the attacker takes on *no market risk*—every step either completes profitably or the whole transaction reverts.

The attacker's goal in this category is almost always one of:

- Make collateral look more valuable than it is, then borrow or mint against it.
- Make debt or a redemption look cheaper than it is, then settle it at a discount.
- Drive a price across a threshold to trigger a liquidation, mint, or payout that pays the attacker.

### Core Attack Flow

```
1. Fund
   |
   Take a flash loan for a large amount of asset X (repaid at tx end)
2. Skew
   |
   Swap X into a low-liquidity pool the victim uses as its price source
3. Trigger
   |
   Call the victim (borrow / mint / redeem / liquidate) while price is distorted
4. Extract & Repay
   |
   Take the mispriced value out, reverse the swap, repay the flash loan
   (all atomic — if any step fails, everything reverts)
```

## Common Attack Patterns

### 1. Flash-Loan Skew of a Spot DEX Price

The victim reads a pool's reserves as its price. The attacker moves those reserves with a flash-loaned swap in the same transaction.

```solidity
// Victim prices collateral from a single pool's reserves
(uint112 r0, uint112 r1, ) = pair.getReserves();
uint price = uint(r1) * 1e18 / uint(r0);     // attacker-controllable

// Attacker, atomically:
// 1) flashLoan(bigAmountOfToken0)
// 2) pair.swap(...) -> dumps token0, r0 up, r1 down -> price of token0 collapses
//    (or the reverse to inflate it, depending on which side is collateral)
// 3) victim.borrow(collateral) reads the skewed price and over-lends
// 4) reverse swap, repay flashLoan, keep the difference
```

**Payoff**: the victim lends against a price the attacker set. The theft is bounded by the victim's liquidity, not the attacker's capital.

### 2. `getAmountsOut` as a "Price Feed"

Using the router's swap quote is the same spot value with a friendlier name.

```solidity
// Victim
uint[] memory amts = router.getAmountsOut(1e18, [WETH, TOKEN]);
uint price = amts[1];                         // instantaneous, movable

// Attacker moves the pool first, then the quote returns whatever they want.
```

**Payoff**: identical to reading reserves—`getAmountsOut` offers no manipulation resistance.

### 3. `balanceOf` / Donation Inflation

The victim infers value from a contract's token balance, which anyone can raise with a direct transfer or a swap.

```solidity
// Victim assumes share price = balance / supply
uint pricePerShare = token.balanceOf(vault) * 1e18 / vault.totalSupply();

// Attacker donates or swaps tokens into `vault` to spike balanceOf,
// mints/redeems at the inflated pricePerShare, then recovers the donation.
```

**Payoff**: shares are minted or redeemed at a value that does not reflect reality. Empty or low-supply vaults are especially exposed.

### 4. LP-Token Mispricing

The victim values an LP token from the pool's live underlying balances rather than a manipulation-resistant fair-value formula.

```solidity
// Naive LP valuation — moves with the pool's instantaneous reserves
uint lpValue = (reserve0 * price0 + reserve1 * price1) / lpToken.totalSupply();

// Attacker skews the pool so reserve0/reserve1 misrepresent true holdings,
// then borrows against the over-valued LP token.
```

**Payoff**: over-valued LP collateral unlocks borrowing or minting against value that does not exist.

### 5. Single-Source Dependence

When one venue is the only source, manipulating that one venue is the whole attack.

```solidity
uint price = onePool.spot();   // no second source to disagree

// Attacker only has to move `onePool`. A deep-pool assumption is not a control:
// the attacker picks the cheapest venue the victim actually reads.
```

**Payoff**: no cross-check means no alarm—the distorted price is accepted as truth.

### 6. Stale / Frozen Feed Exploitation

Even a robust feed is dangerous if freshness is unchecked. A frozen or lagging value diverges from the real market.

```solidity
(, int answer, , uint updatedAt, ) = feed.latestRoundData();
uint price = uint(answer);      // updatedAt ignored -> stale price accepted

// If the market has moved but the read value has not, the attacker trades
// against the gap: buy cheap where the contract thinks it is dear, or vice versa.
```

**Payoff**: the contract acts on yesterday's price; the attacker pockets the difference against today's.

### 7. Liquidation-Threshold Manipulation

The attacker pushes the price just across a health/liquidation boundary to force or capture a liquidation.

```solidity
// Victim liquidation engine reads a manipulable price for "isUnderwater"
if (spotPrice(collateral) * amount < debt * threshold) {
    liquidate(position);        // seize collateral at a discount
}

// Attacker briefly depresses spotPrice to mark a healthy position as underwater,
// liquidates it, and seizes collateral far below its real value.
```

**Payoff**: healthy positions are force-liquidated and their collateral is bought at a manipulated discount.

### 8. Mint / Redeem Mispricing

Any function that issues or redeems a token against a manipulable price becomes a value-extraction function.

```solidity
// Mint synthetic at attacker-inflated collateral price -> over-minted
uint minted = collateralAmount * spotPrice / 1e18;

// Or redeem at an attacker-depressed backing price -> drains the reserve.
```

**Payoff**: over-minting breaks the peg/backing; mispriced redemption drains the reserve.

## Chaining and Amplifying the Manipulation

Individually, each read looks reasonable. Combined with flash-loan atomicity, they form a complete, risk-free exploit:

```
Flash-loan a large amount of the quote asset
        +
Swap into a low-liquidity pool the victim prices from   -> skew the spot price
        +
Deposit collateral / call borrow while the price is distorted
        +
Withdraw the over-credited value, reverse the swap, repay the loan
        =  protocol left insolvent, attacker keeps the difference, one transaction
```

A second common shape targets the liquidation path:

```
Depress the collateral's spot price with a flash-loaned swap
        -> a healthy position now reads as underwater
        -> attacker liquidates it and seizes the collateral cheaply
        -> reverse the swap and repay; the seized collateral is the profit
```

## Key Takeaways

1. **Manipulation is market mechanics, not a payload**—the attacker moves a price the victim trusts.
2. **Flash loans remove the cost barrier**—assume unlimited atomic capital and no attacker market risk.
3. **Spot reads are the common thread**—reserves, `getAmountsOut`, `balanceOf`, and naive LP valuations all move in one transaction.
4. **Thresholds are targets**—liquidation, mint, and redemption boundaries are exactly where a nudged price pays off.
5. **One source is one point of failure**—no cross-check means the distorted value is simply believed.

## Next Steps

- **[Prevention Guide](prevention.md)**: Build a manipulation-resistant pricing strategy
- **[Code Examples](examples.md)**: See vulnerable spot oracles vs. secure Chainlink/TWAP code
- **[Smart Contract Top 10](/learn/smart-contract)**: Return to the full lesson index
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
