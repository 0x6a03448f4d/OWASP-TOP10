# SC10: Denial of Service (DoS) Attacks - Code Examples

These paired examples show how a Denial of Service condition is introduced in Solidity and how to remove it. Each pair puts a **vulnerable** contract next to a **secure** rewrite so you can see exactly what changed. The examples cover the real DoS classes seen on-chain: **push-payment refund DoS**, **unbounded-loop gas DoS**, and **locked-funds griefing**.

> These snippets are for study. They are deliberately minimal and omit access control, events, and full error handling. Do not deploy them as-is.

## On This Page

1. [Push-Payment Refund Loop vs. Pull Payments](#1-push-payment-refund-loop-vs-pull-payments)
2. [Unbounded Loop vs. Pagination / Pull](#2-unbounded-loop-vs-pagination--pull)
3. [Stuck Auction vs. Credit-and-Withdraw](#3-stuck-auction-vs-credit-and-withdraw)
4. [Hard External Dependency vs. Failure Isolation](#4-hard-external-dependency-vs-failure-isolation)
5. [Forced-Balance Griefing vs. Internal Accounting](#5-forced-balance-griefing-vs-internal-accounting)
6. [What Changed / Why Secure](#what-changed--why-secure)

## 1. Push-Payment Refund Loop vs. Pull Payments

The classic DoS. A function pushes ETH to every recipient in a single transaction. If one recipient is a contract whose `receive()` reverts (a "poison" recipient), the whole loop reverts and *nobody* gets paid — forever.

### Vulnerable: refund all bidders in one push loop

```solidity
// VULNERABLE: one reverting recipient blocks the entire refund
contract Sale {
    address[] public buyers;
    mapping(address => uint256) public paid;

    function refundEveryone() external {
        for (uint256 i = 0; i < buyers.length; i++) {
            address buyer = buyers[i];
            uint256 amount = paid[buyer];
            paid[buyer] = 0;
            // .transfer forwards 2300 gas and REVERTS on failure.
            // A single poison buyer reverts the whole transaction,
            // so no one in the list is ever refunded.
            payable(buyer).transfer(amount);
        }
    }
}
```

> **Why it breaks:** a buyer can be a contract with `receive() external payable { revert(); }`. Once such an address is in `buyers`, `refundEveryone()` reverts every time it is called — a permanent freeze that any single participant can trigger.

### Secure: pull pattern — each user withdraws their own funds

```solidity
// SECURE: per-user accounting; one failure is isolated to that user
contract Sale {
    mapping(address => uint256) public pendingRefund;

    // Record what each user is owed. No external call here.
    function _creditRefund(address user, uint256 amount) internal {
        pendingRefund[user] += amount;
    }

    // Each user pulls independently. A poison caller only breaks
    // their OWN withdrawal; everyone else is unaffected.
    function withdrawRefund() external {
        uint256 amount = pendingRefund[msg.sender];
        require(amount > 0, "nothing to withdraw");
        pendingRefund[msg.sender] = 0;                 // effects BEFORE interaction
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "withdraw failed");
    }
}
```

The mechanism no longer depends on any single transfer succeeding. This is the single most important DoS defense.

## 2. Unbounded Loop vs. Pagination / Pull

A function that loops over an array users can grow will eventually cost more gas than the block gas limit allows — at which point it can *never* execute again. An attacker can accelerate this by cheaply adding many entries.

### Vulnerable: iterate a user-growable array

```solidity
// VULNERABLE: gas cost grows with participants until it exceeds
// the block gas limit and the function becomes permanently uncallable
contract Rewards {
    address[] public participants;

    function join() external {
        participants.push(msg.sender);   // anyone can grow the array
    }

    function distribute(uint256 share) external {
        for (uint256 i = 0; i < participants.length; i++) {
            payable(participants[i]).transfer(share);   // unbounded work
        }
    }
}
```

> **Why it breaks:** nothing caps `participants.length`. Once the loop's total gas passes the block limit, `distribute()` reverts on out-of-gas for everyone, locking the distribution.

### Secure option A: pull — no loop at all

```solidity
// SECURE: O(1) per user, no sweep over an unbounded array
contract Rewards {
    mapping(address => uint256) public owed;

    function claim() external {
        uint256 amount = owed[msg.sender];
        require(amount > 0, "nothing owed");
        owed[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "claim failed");
    }
}
```

### Secure option B: bounded pagination when a loop is unavoidable

```solidity
// SECURE: caller paginates; each call does a hard-capped amount of work
contract Rewards {
    address[] public participants;

    function distributeBatch(uint256 start, uint256 count, uint256 share) external {
        require(count <= 100, "batch too large");        // hard upper bound
        uint256 end = start + count;
        require(end <= participants.length, "out of range");
        for (uint256 i = start; i < end; i++) {
            payable(participants[i]).transfer(share);
        }
    }
}
```

Prefer per-user mappings over arrays you must sweep. When a loop is truly required, cap the per-call iteration count and let callers paginate.

## 3. Stuck Auction vs. Credit-and-Withdraw

A "refund-on-outbid" auction pushes the previous leader's bid back to them when a new bid arrives. If the current leader is a contract that rejects ETH, the refund reverts, so *no new bid can ever succeed* — the attacker stays the highest bidder forever and the auction is frozen.

### Vulnerable: push the refund inside `bid()`

```solidity
// VULNERABLE: a poison leader permanently blocks all future bids
contract Auction {
    address public highestBidder;
    uint256 public highestBid;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (highestBidder != address(0)) {
            // If the outgoing leader rejects ETH, this reverts and
            // NO ONE can outbid them. The auction is stuck.
            payable(highestBidder).transfer(highestBid);
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }
}
```

> **Why it breaks:** the new bid depends on a successful payment to an untrusted party. An attacker bids from a contract with a reverting `receive()`, then every later `bid()` reverts on the refund step.

### Secure: credit the old bidder, let them withdraw

```solidity
// SECURE: refund becomes a pull credit; a new bid never depends
// on paying the previous bidder
contract Auction {
    address public highestBidder;
    uint256 public highestBid;
    mapping(address => uint256) public refunds;

    function bid() external payable {
        require(msg.value > highestBid, "bid too low");
        if (highestBidder != address(0)) {
            refunds[highestBidder] += highestBid;   // credit, do NOT transfer
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdrawRefund() external {
        uint256 amount = refunds[msg.sender];
        require(amount > 0, "nothing to withdraw");
        refunds[msg.sender] = 0;
        (bool ok, ) = payable(msg.sender).call{value: amount}("");
        require(ok, "refund failed");
    }
}
```

A poison previous bidder can no longer block new bids — their refund simply waits for them to pull it.

## 4. Hard External Dependency vs. Failure Isolation

A critical path that *must* call an external contract inherits that contract's failures. If the dependency is paused, self-destructed, or simply reverts, the caller is bricked. The fix is to isolate the call so its failure is handled, not fatal.

### Vulnerable: a required external call with no fallback

```solidity
// VULNERABLE: if the oracle reverts, is paused, or self-destructs,
// every settlement reverts and funds are stuck
interface IPriceFeed { function latestPrice() external view returns (uint256); }

contract Market {
    IPriceFeed public oracle;   // fixed, non-swappable

    function settle(uint256 qty) external {
        uint256 price = oracle.latestPrice();   // hard dependency, no try/catch
        // ... settlement logic that can never run if the call fails ...
    }
}
```

> **Why it breaks:** the whole settlement path reverts whenever the external call reverts. A dependency that can be paused or destroyed is a latent, permanent freeze of every function that touches it.

### Secure: swappable dependency + graceful failure

```solidity
// SECURE: try/catch isolates the failure; the oracle is replaceable
// under timelocked governance so a broken dependency can be swapped out
interface IPriceFeed { function latestPrice() external view returns (uint256); }

contract Market {
    address public oracle;   // updatable via timelocked governance

    function currentPrice() public view returns (uint256 price, bool ok) {
        try IPriceFeed(oracle).latestPrice() returns (uint256 p) {
            return (p, true);
        } catch {
            return (0, false);   // caller decides how to handle; no hard revert
        }
    }

    function settle(uint256 qty) external {
        (uint256 price, bool ok) = currentPrice();
        require(ok, "price unavailable, retry later");   // isolated, recoverable
        // ... settlement logic ...
    }
}
```

One misbehaving dependency now yields a clean, recoverable error instead of a permanent lockup, and governance can point at a replacement feed.

## 5. Forced-Balance Griefing vs. Internal Accounting

ETH can be force-sent to any contract via `selfdestruct` (or a pre-computed address), bypassing `receive()`. Logic that trusts `address(this).balance` — especially an exact-equality check — can be permanently jammed by a griefer who nudges the balance off the expected value.

### Vulnerable: exact-balance check an attacker can break

```solidity
// VULNERABLE: forced ETH makes the equality permanently false,
// so finalize() can never succeed
contract Crowdfund {
    uint256 public goal;

    function finalize() external {
        // An attacker selfdestructs 1 wei into this contract so the
        // balance is goal + 1, and this require() reverts forever.
        require(address(this).balance == goal, "not exactly at goal");
        // ... release funds ...
    }
}
```

> **Why it breaks:** `address(this).balance` is not fully under the contract's control. Forced ETH cannot be blocked, so any invariant that depends on an exact balance can be griefed into a permanent revert.

### Secure: track deposits internally and use `>=`

```solidity
// SECURE: internal counter the contract controls; never trust raw balance
contract Crowdfund {
    uint256 public goal;
    uint256 public totalDeposited;

    function deposit() external payable {
        totalDeposited += msg.value;    // counted only through the intended path
    }

    function finalize() external {
        // Forced ETH does not change totalDeposited, and >= cannot be
        // pushed past by adding funds, so this can't be griefed.
        require(totalDeposited >= goal, "goal not reached");
        // ... release funds ...
    }
}
```

Internal accounting plus a `>=` comparison removes the attacker's ability to jam the invariant with force-sent ETH.

## What Changed / Why Secure

| # | Vulnerable Pattern | Secure Pattern | Why It Is Secure |
|---|--------------------|----------------|------------------|
| 1 | Push refund to all recipients in one loop | Pull payments (`withdrawRefund` per user) | A poison recipient's failure is isolated to that user; the mechanism never depends on one transfer succeeding |
| 2 | Unbounded loop over a user-growable array | Per-user mapping (pull) or hard-capped pagination | Work per call is O(1) or bounded, so it always fits under the block gas limit no matter how many users join |
| 3 | Auction pushes refund to outbid leader | Credit the old bidder, they withdraw later | A new bid no longer depends on paying an untrusted party, so a poison leader can't freeze the auction |
| 4 | Critical path hard-depends on an external call | `try/catch` isolation + swappable dependency | A paused, reverting, or destroyed dependency yields a recoverable error instead of a permanent lockup |
| 5 | Exact check on `address(this).balance` | Internal deposit counter with `>=` | Force-sent ETH can't move the tracked total, so the invariant can't be griefed into a permanent revert |

> **One rule ties them together:** never let one participant's failure — or one unbounded cost — become everyone's failure. Isolate failures per user, bound every loop, and never make a critical path depend on an untrusted external outcome.

## Next Steps

- **[Overview](overview.html)**: What DoS means for smart contracts and why it matters
- **[Attack Vectors](attack-vectors.html)**: The full catalog of how DoS is triggered on-chain
- **[Prevention](prevention.html)**: The complete defensive checklist behind these examples
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
