# SC07: Flash Loan Attacks - Overview

## Table of Contents

- [What is a Flash Loan Attack?](#what-is-a-flash-loan-attack)
- [Why Does This Matter?](#why-does-this-matter)
- [Technical Context](#technical-context)
- [Real-World Impact](#real-world-impact)
- [Prevalence and Severity](#prevalence-and-statistics)
- [Common Misunderstandings](#common-misunderstandings)

## What is a Flash Loan Attack?

A **flash loan** is an uncollateralised loan that must be borrowed and repaid **within a single transaction**. Because the Ethereum Virtual Machine executes a transaction atomically—every state change either commits together or reverts together—a lending protocol can safely hand an attacker millions in tokens with no collateral: if the loan plus its fee is not returned by the end of the same transaction, the entire transaction reverts as if it never happened. The lender is never at risk.

**Flash loans are not themselves a vulnerability.** They are a legitimate DeFi primitive used for arbitrage, collateral swaps, and self-liquidation. The security problem is that they are a devastating *amplifier*: they let anyone temporarily wield an enormous amount of capital—far more than they own—for the duration of one transaction. Capital that used to be the exclusive privilege of whales is now rentable by the block. A **flash loan attack** is therefore not an exploit of the loan; it is the use of borrowed capital to *weaponise some other weakness* in a victim protocol at a scale that would otherwise be impossible.

Mental model: a flash loan does not create a new door into a protocol. It hands the attacker a battering ram large enough to walk through a door the protocol left unlocked—a manipulable price feed, a naive vote count, an accounting rounding bug—and then hands the ram back before anyone can react.

### Core Concept

```
The atomic flash-loan attack pattern (all inside ONE transaction):

  1. BORROW      -> take a huge uncollateralised loan (e.g. 100,000,000 tokens)
  2. MANIPULATE  -> use that capital to distort shared state the victim trusts:
                    - skew a spot-price AMM pool
                    - inflate/deflate a governance vote balance
                    - trigger a mispriced mint / redeem / liquidation
  3. EXTRACT     -> trade, borrow, redeem, or vote against the victim at the
                    manipulated state, draining value into the attacker
  4. REPAY       -> return the loan + fee to the lender
  5. PROFIT      -> keep the difference

  If step 3 does not yield enough to satisfy step 4, the WHOLE transaction
  reverts -> the attacker loses only gas. The attack is effectively RISK-FREE.
```

### Why the Atomicity Matters

Two properties of a single transaction make the attack work:

- **Enormous, free capital**: the attacker controls a balance they could never afford, so any protocol whose behaviour depends on "how much does this actor hold right now" or "what is the price right now" can be pushed to an extreme.
- **All-or-nothing execution**: because an unprofitable attempt reverts, the attacker never loses the principal. They can simulate and re-submit until the numbers work. There is no downside to trying, which is why these attacks are attempted constantly.

## Why Does This Matter?

### Business Impact

- **Direct Protocol Drainage**: A single transaction can empty a lending pool, vault, or AMM of its reserves, wiping out user deposits in seconds.
- **Governance Capture**: If voting power is read from current token balance, an attacker can borrow a controlling stake, pass or block a proposal, and repay—seizing control of a treasury or upgrade key without ever owning the tokens.
- **Loss of User Trust and TVL**: A protocol that suffers a flash-loan drain typically sees Total Value Locked collapse as depositors flee, often permanently.
- **Cascading Insolvency**: Protocols that consume a manipulated price (money markets, stablecoins, derivatives) can be pushed into bad debt that outlives the transaction.

### Technical Impact

- **Oracle Manipulation at Scale**: Spot-price oracles reading a single AMM pool can be skewed arbitrarily for one transaction, feeding a false price to any victim that trusts them (see **SC02: Price Oracle Manipulation**).
- **Amplified Logic/Accounting Errors**: A rounding error or mispriced share that is negligible at small size becomes a full drain when applied to nine-figure capital (see **SC03: Logic Errors**).
- **Reentrancy Amplification**: Flash-borrowed capital combined with a reentrancy flaw multiplies the value extracted per callback (see **SC05: Reentrancy**).
- **Liquidation Gaming**: An attacker can force a victim position underwater by moving the reference price, then liquidate it for the bonus—or protect their own position from fair liquidation.

## Technical Context

### How Flash Loans Weaponise Other Weaknesses

#### 1. Price-Oracle Manipulation

The most common flash-loan attack class. A victim protocol prices an asset using the *spot* ratio of a liquidity pool. The attacker borrows a huge amount, dumps it into the pool to skew that ratio, then interacts with the victim (borrow, mint, redeem) while the price is wrong, and finally reverses the swap.

```
// Victim reads price from a single pool's CURRENT reserves:
uint price = reserveQuote / reserveBase;   // spot price = trivially skewable

// Attacker (one tx):
//   flashBorrow(baseToken, 50_000_000)
//   pool.swap(base -> quote)     // reserves distorted, price crashes/spikes
//   victim.borrowAgainst(base)   // over-borrows at the fake price
//   pool.swap(quote -> base)     // unwind
//   flashRepay(baseToken, 50_000_000 + fee)
```

#### 2. Governance Attacks

If a governance contract counts votes from the voter's *current* token balance, an attacker can borrow enough governance tokens to reach quorum, cast a vote, and repay—all atomically. Because proposal execution and voting can be forced into one transaction (or a flash-mintable vote token is used), a flash loan buys temporary control.

```
// Vulnerable: voting power = balanceOf(msg.sender) AT VOTE TIME
uint votes = govToken.balanceOf(msg.sender);   // flash-borrowed balance counts!
```

#### 3. Draining via Logic / Accounting Errors

Vaults that compute share price, fees, or rewards with a flawed formula are safe at retail size but catastrophic at scale. Flash capital turns a tiny per-unit error into a total drain.

```
// e.g. first-depositor share inflation, rounding in favour of the caller,
// or reward accrual that scales with a manipulable balance snapshot
```

#### 4. Liquidation and Collateral/Debt Manipulation

By moving the price that a money market uses for health checks, an attacker can make a healthy position appear insolvent (then liquidate it at a discount) or make an unhealthy position appear safe (dodging fair liquidation), or mint under-collateralised debt against inflated collateral.

#### 5. Arbitrage-Based Value Extraction

Where two protocols disagree on price, flash capital lets an attacker extract the *entire* spread in one shot rather than a small slice—sometimes benign arbitrage, sometimes the mechanism that realises a manipulation.

### The Building Blocks an Attacker Combines

| Primitive Borrowed With Flash Capital | Weakness It Targets | Result |
| --- | --- | --- |
| Massive one-tx swap | Spot-price oracle (SC02) | False price fed to victim, over-borrow / mis-mint |
| Massive one-tx token balance | Balance-based voting | Governance proposal passed / blocked |
| Massive deposit / redeem | Share-price / rounding logic (SC03) | Vault drained via inflated shares |
| Massive callback value | Missing reentrancy guard (SC05) | Repeated withdrawal beyond balance |
| Massive collateral swing | Liquidation health check | Forced or dodged liquidation |

## Real-World Impact

The incidents below are described as **classes** of well-documented DeFi attacks. Specific protocol names and dollar figures vary by source and are deliberately omitted; the patterns, not the headlines, are what matter for defence.

### Case Study 1: Flash-Loan-Amplified Oracle Manipulation

**Pattern**:

- A lending or synthetic-asset protocol priced collateral from the spot reserves of a single on-chain AMM pool.
- Attackers flash-borrowed a large sum, swapped to skew that pool's price, then borrowed or minted against the mispriced asset before unwinding the swap and repaying the loan.

**Impact**: The protocol issued far more debt or synthetic tokens than the real collateral value supported, leaving it insolvent once the price snapped back.

**Root Cause**: Trusting a single-block, single-source spot price that flash capital can move at will. The fix class is robust oracles (TWAP / multi-source), covered in SC02.

### Case Study 2: Flash-Loan Governance Takeover

**Pattern**:

- A governance system tallied voting power from the current token balance at the moment of voting.
- An attacker flash-borrowed a large quantity of the governance token, submitted or passed a proposal that transferred value or altered parameters in their favour, and repaid the loan—all in one transaction.

**Impact**: Temporary but decisive control of on-chain governance, used to authorise value extraction.

**Root Cause**: Voting weight read from a live, flash-inflatable balance instead of a snapshot from a past block, with no execution timelock.

### Case Study 3: Flash-Loan-Amplified Accounting / Reentrancy Drain

**Pattern**:

- A vault or pool contained a share-pricing, reward, or reentrancy flaw that was harmless at small scale.
- Attackers supplied flash-borrowed capital so the same flawed path moved a catastrophic amount of value in a single transaction.

**Impact**: The pool's reserves were drained in one transaction.

**Root Cause**: A logic/accounting or reentrancy weakness (SC03 / SC05) that was never stress-tested against an attacker holding effectively unlimited capital for one transaction.

## Prevalence and Severity

Flash-loan-amplified attacks are among the **most damaging and most frequently attempted** exploit classes in DeFi. Because attempts are risk-free (an unprofitable attempt simply reverts and costs only gas), profitable opportunities are probed continuously by automated bots.

Rather than cite specific figures, the defensible picture is:

- Flash loans are the **standard amplifier** layered on top of oracle, governance, and accounting bugs—most large DeFi drains of the spot-price era involved one.
- The **root vulnerability is almost never the loan**; it is the victim's reliance on a manipulable price, balance, or formula.
- Severity is rated **critical**: a single transaction can achieve total loss of a pool's funds or capture of its governance.

Note: exact loss totals differ between reports. The durable takeaway is that if any part of your protocol can be gamed by an actor with temporary near-infinite capital, a flash loan will find it—cheaply, repeatably, and without warning.

## Common Misunderstandings

### Myth 1: "We should block flash loans to be safe"

**Reality**: You usually cannot reliably block them, and it treats the symptom. Flash loans only expose weaknesses that already exist. A protocol whose prices, votes, and accounting are sound is not harmed by an attacker holding a large balance for one transaction. Fix the underlying trust in manipulable state.

### Myth 2: "Flash loans are the vulnerability"

**Reality**: The flash loan is the amplifier, not the flaw. The vulnerability is a spot-price oracle, a balance-based vote, a rounding bug, or a missing reentrancy guard. Remove those and the amplifier has nothing to amplify.

### Myth 3: "An attacker can't afford to move our price"

**Reality**: With a flash loan they can afford to move almost any on-chain price for one transaction, because the capital is free and returned instantly. Assume the attacker has effectively unlimited capital for the length of a transaction.

### Myth 4: "Our TWAP-free oracle is fine because manipulation is expensive"

**Reality**: Cost-of-manipulation arguments assume the attacker must hold capital and bear risk. Flash loans remove both. Spot manipulation that would be prohibitively expensive with owned capital becomes free with borrowed capital.

### Myth 5: "Requiring tokens to vote means only real holders vote"

**Reality**: If voting power is read from the live balance, a flash borrower *is* a real holder for that transaction. Only a snapshot from a past block distinguishes committed holders from flash borrowers.

### Myth 6: "A tiny rounding error can't be exploited"

**Reality**: Multiply any per-unit error by flash-borrowed nine-figure capital and it stops being tiny. Attackers scale the input until the error becomes a drain.

## How Flash Loan Attacks Relate to Other Categories

| Aspect | Flash Loan Attacks (SC07) | Price Oracle Manipulation (SC02) | Reentrancy (SC05) |
| --- | --- | --- | --- |
| **Role** | Amplifier / capital source | The weakness being amplified | The weakness being amplified |
| **Root cause** | Trusting manipulable state at scale | Manipulable spot price feed | State updated after external call |
| **Typical fix** | Design for infinite one-tx capital | TWAP / robust multi-source oracle | CEI + reentrancy guard |
| **Relationship** | Weaponises SC02/SC03/SC05 at scale | Frequently the SC07 payload | Frequently the SC07 payload |

## Key Takeaways

1. **Flash loans amplify, they do not create**—the real bug is a manipulable price, vote, or formula the loan wields at scale.
2. **Assume unlimited one-transaction capital**—design every mechanism as if an attacker can momentarily hold any balance.
3. **Never trust single-block snapshots**—spot prices and live balances can be distorted for exactly one transaction.
4. **Governance must use past-block snapshots and timelocks**—so a flash-borrowed balance cannot vote.
5. **Attacks are risk-free to attempt**—unprofitable tries just revert, so any exploitable gap will be found and used.

## How to Identify if You're Vulnerable

Ask these questions about your protocol:

- [ ] Does any pricing logic read a **spot** price from a single AMM pool's current reserves?
- [ ] Does governance count voting power from a **current** balance rather than a past-block snapshot?
- [ ] Can a proposal be created, voted on, and executed within a single transaction (no timelock)?
- [ ] Would any accounting formula (share price, rewards, fees) misbehave if fed a nine-figure input?
- [ ] Do any state-changing paths make external calls before updating internal state (reentrancy)?
- [ ] Does any liquidation or health check rely on an instantaneously manipulable price?
- [ ] Have you tested each mechanism assuming the caller holds effectively unlimited capital for one transaction?
- [ ] Are there deviation bounds, sanity checks, or circuit breakers on prices and large swings?

If you answered "yes" or "not sure" to several of these, you are likely exposed to flash-loan amplification today.

## Next Steps

- **Attack Vectors**: How attackers assemble and chain a flash-loan exploit
- **Prevention**: Design assuming infinite one-tx capital—TWAP, snapshots, guards
- **Examples**: Vulnerable vs. secure Solidity, side by side
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
