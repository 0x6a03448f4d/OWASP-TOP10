# SC06: Unchecked External Calls - Attack Vectors

## Table of Contents

- [Understanding Unchecked-Call Attack Vectors](#understanding)
- [Core Attack Flow](#core-attack-flow)
- [Common Attack Patterns](#common-attack-patterns)
- [Chaining Unchecked Calls](#chaining)

## Understanding Unchecked-Call Attack Vectors

**&#9888; EDUCATIONAL PURPOSE ONLY** — the techniques below are shown so you can find and fix these issues in contracts you own or are authorised to test.

Unchecked external calls are rarely exploited with an exotic payload. They are exploited by **making a call fail on purpose**—or by **supplying a token that behaves differently from the standard**—and then letting the victim contract march forward on its false assumption of success. Because the flaw is a missing check rather than a logic error you can see, it often survives review and testing (which usually uses well-behaved recipients and standard tokens).

The attacker's goal in this category is usually one of:

- Force a value-moving call to return `false` (or return unexpected data) while the victim treats it as success.
- Get internal balance credited for value that never actually arrived (phantom deposit).
- Cause funds to be permanently stranded, or a shared payout loop to be bricked, by being an uncooperative recipient.

### Core Attack Flow

```
1. Identify
   &darr;
   Find a send()/call()/transfer() whose return value is never checked
2. Position
   &darr;
   Become the recipient, the token, or the depositor in that flow
3. Trigger
   &darr;
   Make the call fail (reject ETH / return false) or return odd data
4. Profit / Grief
   &darr;
   Victim updates state as if it worked -> stuck funds, phantom credit,
   corrupted accounting, or a permanently blocked payout
```

## Common Attack Patterns

### 1. Rejecting Ether to Strand a Withdrawal

A withdrawal zeroes the internal balance and then sends ether with an unchecked `send`/`call`. A malicious or simply incompatible recipient makes the transfer fail; the balance is already gone.

```
// Victim
function withdraw() external {
    uint256 amt = balances[msg.sender];
    balances[msg.sender] = 0;         // effect applied
    msg.sender.send(amt);             // returns false, NOT checked
}                                     // ether never leaves; balance is now 0

// Attacker contract: no payable receive/fallback, so send() returns false
contract Rejector {
    // (intentionally) cannot accept ETH -> every send to it fails
}
```

**Payoff**: the attacker's own funds are stuck—usually a self-inflicted grief—but the same pattern in a shared loop (below) lets one recipient block everyone.

### 2. Phantom Deposit via a Non-Standard Token

A vault assumes `transferFrom` reverts on failure and credits the deposit without checking the boolean.

```
// Victim
function deposit(uint256 amount) external {
    token.transferFrom(msg.sender, address(this), amount); // return ignored
    shares[msg.sender] += amount;      // credited even though nothing moved
}

// Attacker-supplied token returns false instead of reverting on a failed transfer
function transferFrom(address, address, uint256) external returns (bool) {
    return false;                      // no revert, no tokens moved
}
```

**Payoff**: the attacker is credited shares/balance for tokens the contract never received—then withdraws real value against phantom credit.

### 3. Return-Nothing (USDT-Class) Tokens

Some tokens return *no data* from `transfer`/`transferFrom`. Code that expects a `bool` either reverts on the ABI decode (bricking the integration) or, with a raw call, misreads the empty return.

```
// This reverts for tokens whose transfer returns no data:
require(IERC20(t).transfer(to, amt), "transfer failed");
// The high-level call tries to decode a bool that isn't there.
```

**Payoff**: markets or vaults integrating such tokens become unusable (denial of service) or mishandle the result—depending on how the return is decoded.

### 4. Griefing a Shared Payout Loop

A contract pushes funds to many recipients in a loop with an unchecked (or naively-checked-with-revert) transfer. One recipient that always reverts can block the entire distribution.

```
// Victim distributes to all winners in one call
for (uint256 i = 0; i < winners.length; i++) {
    winners[i].transfer(prize);   // one reverting winner blocks the whole loop
}
```

**Payoff**: a single malicious recipient (reverting fallback, or gas-guzzling fallback) prevents everyone else from being paid—classic push-payment denial of service.

### 5. Masking a Failed delegatecall

An executor/proxy performs a `delegatecall` without checking success. An implementation that reverts is treated as if it ran.

```
function execute(address impl, bytes calldata data) external onlyOwner {
    impl.delegatecall(data);   // success flag discarded
    executed = true;           // recorded as done even if impl reverted
}
```

**Payoff**: the caller records a state transition (upgrade applied, action performed) that never happened, desynchronising the proxy from its implementation.

### 6. Gas-Stipend Failures with transfer/send

`address.transfer` and `send` forward only 2300 gas. A legitimate recipient whose `receive`/`fallback` needs more gas (smart-contract wallets, contracts that emit events on receipt) will fail the transfer—which an unchecked `send` then ignores.

```
// Recipient's fallback does slightly more than 2300 gas of work -> send() fails
receive() external payable { emit Received(msg.sender, msg.value); } // may exceed 2300
```

**Payoff**: transfers to otherwise-valid contract recipients silently fail; combined with an eager state update, their funds are stranded.

### 7. Ignoring Partial Failure in Batch Calls

A multicall aggregates several external calls and returns overall success even when individual legs failed.

```
for (uint256 i = 0; i < targets.length; i++) {
    targets[i].call(payloads[i]);   // each return ignored
}
allSucceeded = true;                // false if any leg failed silently
```

**Payoff**: the batch is recorded as fully applied while some operations never executed—leaving inconsistent, half-applied state.

## Chaining Unchecked Calls

Individually minor gaps combine into a real loss:

```
Non-standard token returns false   -> deposit credits phantom shares
        +
Withdrawal path checks nothing      -> attacker redeems phantom shares
        =  real assets drained against value that never arrived
```

Another common chain:

```
Push-payment loop with unchecked/reverting transfer
        -> attacker registers a reverting recipient
        -> entire distribution is bricked
        -> protocol must migrate or socially bail out the payout
```

## Key Takeaways

1. **Failure is attacker-controllable**—a recipient can reject ether and a token can return `false` or nothing on demand.
2. **Silent success is the exploit**—the victim's missing check turns a failed call into corrupted state.
3. **Phantom deposits steal, stuck withdrawals strand**—both stem from not reading the return value.
4. **Push payments are grief-prone**—one bad recipient can block a whole loop; prefer pull-over-push.
5. **Non-standard tokens are the norm, not the exception**—assume they will misbehave and handle it.

## Next Steps

- **Prevention Guide**: Return-value checks, SafeERC20, CEI, and pull-over-push
- **Code Examples**: See the vulnerable contract and its secure rewrite
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
