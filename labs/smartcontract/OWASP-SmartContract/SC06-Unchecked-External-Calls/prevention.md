# SC06: Unchecked External Calls - Prevention

## Prevention Strategy Overview

Preventing unchecked external calls comes down to a single discipline applied everywhere value or control leaves your contract: **never assume a call succeeded—prove it, then act**.

1. Capture and require the success flag of every low-level call.
2. Use `SafeERC20` for all token movements so non-standard tokens are handled uniformly.
3. Order state changes with Checks-Effects-Interactions.
4. Prefer pull-over-push so one bad recipient cannot break others.
5. Surface failures explicitly with custom errors, and verify returned data—not just the success bool.

### Core Principles

- **Check every return**: `send`, `call`, `delegatecall`, and `staticcall` hand you a boolean—reading it is mandatory, not optional.
- **Distrust tokens**: assume a token may return `false`, return nothing, or behave oddly; wrap it in `SafeERC20`.
- **Effects before interactions**: finalise internal accounting before the external call, and revert atomically if the call fails.
- **Fail loudly**: on failure, revert with a clear reason so the whole transaction unwinds—never continue on a false success.

## 1. Always Check Low-Level Call Return Values

Capture the tuple and `require` success. Bubble up the revert reason where useful.

```
// Vulnerable: return value ignored
msg.sender.call{value: amount}("");

// Secure: capture and require success
(bool ok, ) = msg.sender.call{value: amount}("");
require(ok, "ETH transfer failed");

// Secure with reason bubbling for calls that may carry a revert message
(bool ok2, bytes memory ret) = target.call(data);
if (!ok2) {
    // forward the original revert reason if present
    assembly { revert(add(ret, 0x20), mload(ret)) }
}
```

The Solidity compiler warns when you discard the return value of a low-level call. Treat that warning as an error in CI.

## 2. Use SafeERC20 for All Token Transfers

OpenZeppelin's `SafeERC20` wraps `transfer`, `transferFrom`, and `approve` so that tokens returning `false` revert, and tokens returning *no data* are accepted—normalising the entire non-standard token population.

```
using SafeERC20 for IERC20;

// Vulnerable: assumes standard bool return, ignores it
token.transferFrom(msg.sender, address(this), amount);

// Secure: reverts on false OR handles empty return data
token.safeTransferFrom(msg.sender, address(this), amount);
token.safeTransfer(to, amount);

// For allowances, avoid the non-standard approve race; use forceApprove / increase
token.forceApprove(spender, amount);
```

`safeTransfer`/`safeTransferFrom` perform the low-level call, require it did not revert, and—only if return data exists—require it decodes to `true`. That is exactly the check hand-written code so often omits.

## 3. Follow Checks-Effects-Interactions

Do all validation, then update state, then interact—so a reverting external call unwinds the whole transaction and leaves storage consistent.

```
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");  // Checks
    balances[msg.sender] -= amount;                            // Effects
    (bool ok, ) = msg.sender.call{value: amount}("");         // Interactions
    require(ok, "transfer failed");   // failure reverts, restoring the balance
}
```

Because the `require` reverts on failure, the earlier `-=` is rolled back atomically—no stranded funds, no phantom state.

## 4. Prefer Pull-over-Push for Payments

Instead of pushing funds to many recipients in a loop (where one failure can block all), record what each account is owed and let them withdraw individually.

```
mapping(address => uint256) public credits;

// Push (record only) — cannot be griefed by a bad recipient
function allocate(address user, uint256 amount) internal {
    credits[user] += amount;
}

// Pull — each user triggers and bears the risk of their own transfer
function claim() external {
    uint256 amount = credits[msg.sender];
    require(amount > 0, "nothing to claim");
    credits[msg.sender] = 0;                       // effect first
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "claim transfer failed");          // only the caller is affected
}
```

## 5. Verify delegatecall / call Success AND Return Data

Success only means "did not revert". If the call is supposed to return data, decode and validate it before acting.

```
function execute(address impl, bytes calldata data)
    external onlyOwner returns (bytes memory)
{
    require(impl.code.length > 0, "impl not a contract"); // guard against EOA/empty
    (bool ok, bytes memory ret) = impl.delegatecall(data);
    require(ok, "delegatecall failed");                  // check success
    return ret;                                          // caller validates data
}
```

Note the explicit *contract existence* check: a low-level `call`/`delegatecall` to an address with no code returns `true`. Without the `code.length` guard, a call to an empty address looks like success.

## 6. Handle Non-Standard and Fee-on-Transfer Tokens

Beyond `SafeERC20`, defend against tokens that transfer a different amount than requested (fee-on-transfer / deflationary) by measuring the real balance delta.

```
function deposit(uint256 amount) external {
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);
    uint256 received = token.balanceOf(address(this)) - before; // actual delta
    shares[msg.sender] += received;   // credit only what truly arrived
}
```

## 7. Surface Failures with Custom Errors

Do not swallow failures. Revert with a specific, gas-efficient custom error so callers and monitoring can react.

```
error EthTransferFailed(address to, uint256 amount);
error TokenTransferFailed(address token, address to, uint256 amount);

function payout(address payable to, uint256 amount) external {
    (bool ok, ) = to.call{value: amount}("");
    if (!ok) revert EthTransferFailed(to, amount);
}
```

## 8. Choosing Between transfer, send, and call

| Method | On failure | Gas forwarded | Recommendation |
| --- | --- | --- | --- |
| `transfer` | Reverts | 2300 (fixed) | Can break valid contract recipients; avoid as default |
| `send` | Returns `false` | 2300 (fixed) | Only if you check the bool; same gas limitation |
| `call{value:}` | Returns `false` | All (adjustable) | **Preferred**: check the bool + add a reentrancy guard |

Modern guidance favours a checked `call` combined with a reentrancy guard and CEI, rather than relying on the rigid 2300-gas stipend of `transfer`/`send`.

## 9. Testing and Tooling

Make the missing check impossible to merge:

```
# Static analysis flags unchecked low-level calls and unsafe ERC20 usage
slither .            # detectors: unchecked-lowlevel, unchecked-send, unchecked-transfer
# Treat the compiler's "return value of low-level call not used" as an error
# In tests, use adversarial mocks:
#   - a Rejector contract with no payable fallback
#   - a token that returns false
#   - a token that returns no data (USDT-class)
#   - a fee-on-transfer token
```

Include unit and fork tests that route every value-moving path through these adversarial mocks, and add invariant tests asserting internal accounting always matches actual balances.

## 10. Monitoring and Detection

Even with checks, watch for the signatures of failed interactions in production.

```
// Emit on both success and explicit failure paths so off-chain monitors can react
event TransferSucceeded(address indexed to, uint256 amount);
event TransferReverted(address indexed to, uint256 amount, bytes reason);

// Off-chain: alert on rising TransferReverted rates, or on internal-balance vs
// on-chain-balance drift (an invariant that should always hold).
```

## Key Takeaways

1. **Read every boolean** — capture and `require` the success of `call`/`send`/`delegatecall`/`staticcall`.
2. **Use SafeERC20** — it normalises tokens that return `false` or nothing, exactly the case hand-written code misses.
3. **Effects before interactions** — so a failed call reverts atomically and never strands funds.
4. **Pull, don't push** — isolate each recipient's transfer so one failure cannot brick the rest.
5. **Verify data, not just success** — check returned data and contract existence for `call`/`delegatecall`.

## Next Steps

- **Code Examples**: Vulnerable vs. secure Solidity, side by side
- **Attack Vectors**: Understand what you're defending against
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
