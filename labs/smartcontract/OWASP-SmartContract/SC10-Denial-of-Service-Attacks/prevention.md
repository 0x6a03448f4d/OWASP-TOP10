# SC10: Denial of Service (DoS) Attacks - Prevention

## Prevention Strategy Overview

Preventing DoS is about **never letting one participant's failure become everyone's failure**, and **never letting a cost grow without a bound**:

1. Prefer **pull** over **push** payments—each user withdraws their own funds.
2. Bound every loop; never iterate over user-controlled, unbounded data.
3. Isolate external calls so one failure cannot revert the whole batch.
4. Avoid hard dependencies on contracts that can break; design recovery paths.
5. Use robust ownership and never trust `address(this).balance` for critical logic.

### Core Principles

- **Isolate failure**: one participant misbehaving must affect only that participant, never the shared mechanism.
- **Bound the work**: every operation must fit comfortably inside the block gas limit regardless of how much data users add.
- **Fail per-user, not per-system**: a failed withdrawal for one address should leave everyone else able to withdraw.
- **Design for recovery**: assume dependencies and keys can be lost; provide fallbacks, timelocks, and multisig control.

## 1. Prefer Pull Over Push Payments

The single most important defense. Instead of the contract pushing funds to many recipients, record what each user is owed and let them withdraw it themselves. One user's failure is isolated to that user.

```
// SECURE: pull pattern — per-user accounting, each user withdraws independently
mapping(address => uint256) public pendingWithdrawals;

function allocate(address user, uint256 amount) internal {
    pendingWithdrawals[user] += amount;   // just bookkeeping, no external call
}

function withdraw() external {
    uint256 amount = pendingWithdrawals[msg.sender];
    require(amount > 0, "nothing to withdraw");
    pendingWithdrawals[msg.sender] = 0;   // effects BEFORE interaction
    (bool ok, ) = payable(msg.sender).call{value: amount}("");
    require(ok, "withdraw failed");       // only THIS caller is affected
}
```

If `msg.sender` is a poison contract that rejects ETH, only *their* withdrawal fails. Everyone else is unaffected, and the mechanism keeps working.

## 2. Avoid Unbounded Loops Over User-Controlled Data

Never write a critical function whose gas cost grows with the number of users. Replace batch loops with pull payments, mappings, or explicit pagination.

```
// VULNERABLE: cost grows with participants — eventually unexecutable
function payAll() external {
    for (uint i = 0; i < participants.length; i++) {
        payable(participants[i]).transfer(share);
    }
}

// SECURE option A: pull — no loop at all, O(1) per user
function claim() external {
    uint256 amt = owed[msg.sender];
    owed[msg.sender] = 0;
    (bool ok, ) = payable(msg.sender).call{value: amt}("");
    require(ok);
}

// SECURE option B: bounded pagination when a loop is unavoidable
function processBatch(uint256 start, uint256 count) external {
    uint256 end = start + count;
    require(end <= items.length, "out of range");
    require(count <= 100, "batch too large");   // hard upper bound per call
    for (uint i = start; i < end; i++) {
        _process(items[i]);
    }
}
```

Rules of thumb: cap any per-call iteration count, let callers paginate, and prefer per-user mappings over arrays you must sweep.

## 3. Isolate External Calls; Don't Revert the Whole Batch

When you must interact with many external addresses, do not let one failure roll back the others. Handle failures gracefully and record them instead of reverting.

```
// SECURE: a failed transfer is recorded as a credit, not a revert
function distribute(address[] calldata to, uint256 amount) external {
    require(to.length <= 100, "batch too large");
    for (uint i = 0; i < to.length; i++) {
        // low-level call returns false instead of bubbling a revert
        (bool ok, ) = payable(to[i]).call{value: amount, gas: 2300}("");
        if (!ok) {
            pendingWithdrawals[to[i]] += amount;  // fall back to pull
        }
    }
}
```

A recipient that rejects the push simply gets a pull credit; the loop finishes and the other recipients are paid.

## 4. Don't Let One Participant Block Others

Refund-on-outbid and "displace the incumbent" designs freeze if the incumbent can reject the refund. Convert the refund into a pull credit so a new action never depends on a payment to an untrusted party succeeding.

```
// SECURE auction: credit the old bidder, never push the refund
address public highestBidder;
uint256 public highestBid;
mapping(address => uint256) public refunds;

function bid() external payable {
    require(msg.value > highestBid, "too low");
    if (highestBidder != address(0)) {
        refunds[highestBidder] += highestBid;   // credit, do not transfer
    }
    highestBidder = msg.sender;
    highestBid = msg.value;
}

function claimRefund() external {
    uint256 amt = refunds[msg.sender];
    refunds[msg.sender] = 0;
    (bool ok, ) = payable(msg.sender).call{value: amt}("");
    require(ok);
}
```

Now a poison previous bidder cannot block new bids—their refund simply waits for them to pull it.

## 5. Avoid Hard Dependencies on External Contracts

A required call to a contract that can be paused or self-destructed is a latent freeze. Reduce coupling and provide fallbacks.

- **Validate liveness**: check return data and handle a missing/paused dependency without bricking the whole contract.
- **Provide alternatives**: allow governance to point at a replacement dependency (e.g., a swappable oracle address) behind a timelock.
- **Degrade gracefully**: if a non-critical dependency is unavailable, skip it rather than reverting every path.
- **Avoid delegatecall to destructible libraries**: never make core custody depend on a single external library that could be destroyed.

```
// SECURE: swappable dependency with graceful failure
address public oracle;   // updatable via timelocked governance

function currentPrice() public view returns (uint256 price, bool ok) {
    try IPriceFeed(oracle).latestPrice() returns (uint256 p) {
        return (p, true);
    } catch {
        return (0, false);   // caller decides how to handle, no hard revert
    }
}
```

## 6. Use Pull-Based Withdrawals and Per-User Accounting

Model balances as a mapping the contract updates internally, and expose a single `withdraw()`. This removes loops, isolates failures, and makes reasoning about funds simple.

```
mapping(address => uint256) private balances;

function deposit() external payable { balances[msg.sender] += msg.value; }

function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    balances[msg.sender] -= amount;                 // effects first
    (bool ok, ) = payable(msg.sender).call{value: amount}("");
    require(ok, "transfer failed");                 // isolated to caller
}
```

## 7. Don't Rely on address(this).balance for Critical Logic

ETH can be force-sent via `selfdestruct`, so the raw balance is not fully under the contract's control. Track deposits with internal accounting and avoid exact-equality checks.

```
// VULNERABLE
require(address(this).balance == goal, "not exactly at goal");  // forceable

// SECURE: internal counter you control, and >= not ==
uint256 public totalDeposited;
function deposit() external payable { totalDeposited += msg.value; }

function finalize() external {
    require(totalDeposited >= goal, "goal not reached");  // forced ETH can't block this
    // ...
}
```

## 8. Robust Ownership and Recovery Paths

A single owner key is a single point of failure. Harden privileged control and provide recovery.

- **Use a multisig** (e.g., a Safe) as the owner so no one lost key freezes recovery.
- **Two-step ownership transfer** (`Ownable2Step`) so ownership can never be moved to an address that cannot accept it.
- **Timelocked upgrade / migration path** for genuinely stuck states, with transparency for users.
- **Avoid single-owner escape hatches** as the only recovery mechanism.

```
// SECURE: OpenZeppelin two-step ownership prevents an unrecoverable transfer
import "@openzeppelin/contracts/access/Ownable2Step.sol";

contract Vault is Ownable2Step {
    // pendingOwner must call acceptOwnership(), so ownership can never be
    // stranded at an address that cannot use it.
}
```

## 9. Forward a Bounded Gas Stipend

When you do push value, don't forward all gas to untrusted code that could burn it. Use a small stipend (or the pull pattern) so a gas-griefing recipient cannot exhaust the caller.

```
// A recipient cannot burn the whole tx's gas with only 2300 forwarded.
(bool ok, ) = payable(to).call{value: amount, gas: 2300}("");
if (!ok) { pendingWithdrawals[to] += amount; }   // fall back to pull
```

Note: a fixed 2300-gas stipend intentionally limits what the recipient can do. Because gas costs can change across network upgrades, the pull pattern remains the most robust choice for value transfers.

## 10. Test, Audit, and Monitor for DoS

Make DoS a first-class test target, not an afterthought.

```
// Test with a POISON recipient that rejects ETH
contract RevertOnReceive { receive() external payable { revert(); } }

// A distribution test must PASS even when one recipient is poison:
//   - deploy RevertOnReceive as one of the recipients
//   - call distribute()
//   - assert the OTHER recipients were paid (or credited)
//   - assert the poison recipient can still be handled via pull
```

- **Fuzz array sizes**: prove batch functions stay under a gas ceiling, or are paginated.
- **Gas-bound assertions**: assert critical functions cost less than a safe fraction of the block gas limit.
- **Independent audit**: DoS via push-payment and unbounded loops is a standard audit checklist item.
- **Monitor on-chain**: alert if a critical function starts reverting or approaches the gas ceiling.

## Prevention Checklist

| Control | What It Prevents |
| --- | --- |
| Pull over push payments | Poison-recipient freeze of a whole payout |
| Bounded / paginated loops | Block-gas-limit DoS from growing arrays |
| Isolated external calls (credit on failure) | One revert rolling back the whole batch |
| Refund-as-credit in auctions | Incumbent blocking all future actions |
| Swappable, graceful dependencies | Freeze when an external contract breaks |
| Multisig + two-step ownership | Lost-key lockout of recovery functions |
| Internal accounting, not raw balance | Forced-ETH invariant breakage |

## Key Takeaways

1. **Pull, don't push** — per-user withdrawals isolate every failure to the failing user.
2. **Bound every loop** — nothing critical should scale with unbounded, user-controlled data.
3. **Never let one failure revert the batch** — credit failed recipients and keep going.
4. **Design for recovery** — swappable dependencies, multisig ownership, two-step transfer, timelocks.
5. **Distrust the raw balance** — use internal accounting and `>=` checks, never `==` on `address(this).balance`.

## Next Steps

- **Code Examples**: Vulnerable vs. secure Solidity, side by side
- **Attack Vectors**: Understand what you're defending against
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
