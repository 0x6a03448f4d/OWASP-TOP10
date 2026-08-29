# SC03: Logic Errors - Code Examples

Each pair below shows a **vulnerable** contract and the **secure** version of the same logic in Solidity. The examples focus on the logic errors that dominate real DeFi losses: first-depositor share inflation, rounding leakage, reward double-counting, accounting mismatch, and off-by-one boundaries.

## 1. Vault Share Math (First-Depositor / Inflation)

### Vulnerable
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract NaiveVault {
    IERC20 public immutable asset;
    uint256 public totalShares;
    mapping(address => uint256) public shares;

    constructor(IERC20 _asset) { asset = _asset; }

    function deposit(uint256 amount) external returns (uint256 minted) {
        uint256 totalAssets = asset.balanceOf(address(this));
        // BUG: empty-pool 1:1 rule + rate derived from raw balanceOf.
        // An attacker deposits 1 wei, then DONATES tokens directly to the
        // vault to inflate totalAssets so a victim's deposit rounds to 0.
        minted = (totalShares == 0)
            ? amount
            : (amount * totalShares) / totalAssets;   // truncates DOWN -> 0
        totalShares += minted;
        shares[msg.sender] += minted;
        asset.transferFrom(msg.sender, address(this), amount);
    }
}
```

### Secure
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC4626} from "@openzeppelin/contracts/token/ERC20/extensions/ERC4626.sol";

// Extend the audited ERC-4626 implementation and add a virtual-shares offset,
// which makes the empty-pool exchange rate too expensive to manipulate by
// donation. Track assets internally rather than trusting raw balanceOf.
contract SafeVault is ERC4626 {
    constructor(IERC20 asset_)
        ERC20("Safe Vault Share", "svSHARE")
        ERC4626(asset_)
    {}

    // Virtual shares/assets: the offset blunts the first-depositor attack by
    // seeding a large virtual denominator so rounding-to-zero cannot be forced.
    function _decimalsOffset() internal pure override returns (uint8) {
        return 6;
    }
    // OZ ERC4626 rounds share mints DOWN and redemptions' share burns UP,
    // i.e. always in the vault's favour. Consider also a seeded initial
    // deposit at deployment so totalSupply is never manipulable-from-zero.
}
```

## 2. Rounding Direction (Value Leakage)

### Vulnerable
```solidity
// Fee is truncated in the USER's favour on the way in, and assets owed are
// rounded UP on the way out: both directions leak value to the caller.
function previewDeposit(uint256 assets) public view returns (uint256) {
    // rounds DOWN -> user is charged fewer shares than fair
    return (assets * totalSupply) / totalAssets;
}

function previewWithdraw(uint256 assets) public view returns (uint256) {
    // rounds DOWN the shares to BURN -> user burns fewer shares than fair
    return (assets * totalSupply) / totalAssets;
}
// Net: deposit and withdraw both favour the user; looped, the pool bleeds.
```

### Secure
```solidity
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

// State the rounding direction explicitly, and pick the protocol's favour
// on BOTH sides: fewer shares minted on deposit, more shares burned on
// withdrawal. mulDiv also avoids intermediate-overflow precision loss.
function previewDeposit(uint256 assets) public view returns (uint256) {
    return Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Floor);
}

function previewWithdraw(uint256 assets) public view returns (uint256) {
    return Math.mulDiv(assets, totalSupply, totalAssets, Math.Rounding.Ceil);
}
// Invariant to fuzz: deposit(x) then withdraw() never returns MORE than x.
```

## 3. Reward Accrual (Double-Counting)

### Vulnerable
```solidity
mapping(address => uint256) public stake;
uint256 public rate;            // reward per token per second
uint256 public start;          // single global start timestamp

function claim() external {
    // BUG: uses a fixed 'start' and never advances a per-user checkpoint,
    // so the SAME elapsed period is paid on every call.
    uint256 owed = stake[msg.sender] * rate * (block.timestamp - start);
    rewardToken.mint(msg.sender, owed);
    // no state update: call claim() repeatedly to mint 'owed' again and again
}
```

### Secure
```solidity
uint256 constant PRECISION = 1e18;
mapping(address => uint256) public stake;
mapping(address => uint256) public lastAccrued;
mapping(address => uint256) public rewards;
uint256 public rate;           // scaled by PRECISION

function _accrue(address user) internal {
    uint256 elapsed = block.timestamp - lastAccrued[user];
    if (elapsed > 0 && stake[user] > 0) {
        rewards[user] += (stake[user] * rate * elapsed) / PRECISION;
    }
    lastAccrued[user] = block.timestamp;      // checkpoint ALWAYS advances
}

function claim() external {
    _accrue(msg.sender);                       // settle up to now, once
    uint256 owed = rewards[msg.sender];
    rewards[msg.sender] = 0;                    // effects before interaction
    rewardToken.mint(msg.sender, owed);
}
// Invariant to test: total minted as rewards <= total emissions budgeted.
```

## 4. Accounting & Fee-on-Transfer Tokens

### Vulnerable
```solidity
mapping(address => uint256) public balances;

function deposit(uint256 amount) external {
    // BUG 1: credits the REQUESTED amount, not what actually arrived.
    // BUG 2: ignores transferFrom's return value.
    balances[msg.sender] += amount;
    token.transferFrom(msg.sender, address(this), amount);
    // Fee-on-transfer token delivers (amount - fee), but the ledger says
    // 'amount'. The gap is other users' funds, now withdrawable by attacker.
}
```

### Secure
```solidity
import {SafeERC20, IERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;

mapping(address => uint256) public balances;

function deposit(uint256 amount) external {
    require(amount > 0, "zero amount");
    uint256 before = token.balanceOf(address(this));
    token.safeTransferFrom(msg.sender, address(this), amount);  // reverts on failure
    uint256 received = token.balanceOf(address(this)) - before; // measure reality
    require(received > 0, "nothing received");
    balances[msg.sender] += received;          // credit only what arrived
}
// For rebasing tokens, prefer share-based accounting or an explicit allow-list
// of supported (standard, non-rebasing) tokens.
```

## 5. Off-by-One Boundary (Supply Cap)

### Vulnerable
```solidity
uint256 public constant MAX_SUPPLY = 10_000;
uint256 public minted;

function mint(uint256 qty) external {
    // BUG: strict '<' means the cap can be exceeded by one batch boundary,
    // or (depending on intent) can never actually reach MAX_SUPPLY.
    require(minted + qty < MAX_SUPPLY, "cap");
    minted += qty;
    _mintTo(msg.sender, qty);
}
```

### Secure
```solidity
uint256 public constant MAX_SUPPLY = 10_000;
uint256 public minted;

function mint(uint256 qty) external {
    require(qty > 0, "zero qty");
    // Intended rule stated precisely: total may reach, but not exceed, the cap.
    require(minted + qty <= MAX_SUPPLY, "exceeds cap");
    minted += qty;
    _mintTo(msg.sender, qty);
}
// Boundary tests: qty that lands exactly on MAX_SUPPLY (allowed) and one past
// it (rejected). Fuzz to confirm 'minted' can never exceed MAX_SUPPLY.
```

## 6. Order of Operations (State Transition)

### Vulnerable
```solidity
function withdraw(uint256 amount) external {
    // BUG: interaction before effect. Even setting reentrancy aside, the
    // ledger and the real transfer can diverge if the call path branches,
    // and the state machine passes through an inconsistent state.
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "send failed");
    balances[msg.sender] -= amount;            // effect applied last
}
```

### Secure
```solidity
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");  // checks
    balances[msg.sender] -= amount;                           // effects
    (bool ok, ) = msg.sender.call{value: amount}("");         // interactions
    require(ok, "send failed");
}
// Checks-Effects-Interactions keeps every observable state consistent with
// the invariants and closes the reentrancy window as a side benefit.
```

## What Changed, and Why

| Logic Error | Vulnerable | Secure |
|-------------|------------|--------|
| Vault share math | Empty-pool 1:1 + raw `balanceOf`, donatable | Audited ERC-4626 + virtual-shares offset |
| Rounding | Truncation favours the user on both sides | Explicit `Floor`/`Ceil`, protocol's favour |
| Reward accrual | Checkpoint never advances; period double-paid | `_accrue` advances `lastAccrued` every call |
| Accounting | Credits requested amount; ignores return | Balance-delta credit; `SafeERC20` |
| Boundary | Off-by-one `<` comparison | Precise `<=` with boundary tests |
| Ordering | Interaction before effect | Checks-Effects-Interactions |

## Next Steps

- **[Prevention](prevention.md)**: The full strategy—specify, test, and verify invariants
- **[Attack Vectors](attack-vectors.md)**: How these logic errors are exploited
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
