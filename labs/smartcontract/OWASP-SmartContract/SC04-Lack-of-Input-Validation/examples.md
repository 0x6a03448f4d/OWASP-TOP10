# SC04: Lack of Input Validation - Code Examples

Each pair below shows a **vulnerable** function and the **secure** version of the same logic in Solidity. The examples target the validation gaps that dominate real findings: zero addresses, unbounded amounts, mismatched arrays, out-of-range indexes, unbounded fees, and untrusted token/target addresses. Custom errors are used throughout — they are cheaper than string reverts and self-documenting.

## 1. Zero-Address Check

### Vulnerable
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Ownable {
    address public owner;

    function setOwner(address newOwner) external {
        require(msg.sender == owner, "not owner");
        owner = newOwner;          // newOwner == address(0) bricks the contract
    }
}
```

### Secure
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Ownable {
    address public owner;

    error ZeroAddress();
    error NotOwner();

    function setOwner(address newOwner) external {
        if (msg.sender != owner) revert NotOwner();
        if (newOwner == address(0)) revert ZeroAddress();   // validate first
        owner = newOwner;
    }
}
```

## 2. Amount Bounds

### Vulnerable
```solidity
mapping(address => uint256) public balances;

function transfer(address to, uint256 amount) external {
    balances[msg.sender] -= amount;   // reverts on underflow in 0.8, but
    balances[to]        += amount;    // allows amount == 0 and to == address(0)
}
```

### Secure
```solidity
mapping(address => uint256) public balances;

error ZeroAddress();
error ZeroAmount();
error InsufficientBalance(uint256 have, uint256 want);

function transfer(address to, uint256 amount) external {
    if (to == address(0)) revert ZeroAddress();
    if (amount == 0)      revert ZeroAmount();

    uint256 bal = balances[msg.sender];
    if (amount > bal) revert InsufficientBalance(bal, amount);

    balances[msg.sender] = bal - amount;   // effects after all checks
    balances[to]        += amount;
}
```

## 3. Array Length Equality and Cap

### Vulnerable
```solidity
function airdrop(address[] calldata to, uint256[] calldata amt) external {
    for (uint256 i; i < to.length; ++i) {
        token.transfer(to[i], amt[i]);   // amt may be shorter -> revert;
    }                                    // to may be huge -> gas-limit DoS
}
```

### Secure
```solidity
using SafeERC20 for IERC20;

uint256 constant MAX_BATCH = 200;

error LengthMismatch();
error BatchTooLarge(uint256 len, uint256 max);
error ZeroAddress();

function airdrop(address[] calldata to, uint256[] calldata amt) external {
    if (to.length != amt.length)  revert LengthMismatch();
    if (to.length > MAX_BATCH)     revert BatchTooLarge(to.length, MAX_BATCH);

    for (uint256 i; i < to.length; ++i) {
        if (to[i] == address(0)) revert ZeroAddress();
        token.safeTransfer(to[i], amt[i]);
    }
}
```

## 4. Index / ID Validation

### Vulnerable
```solidity
struct Ticket { address owner; uint256 value; }
Ticket[] public tickets;

function redeem(uint256 id) external {
    Ticket storage t = tickets[id];       // id out of range -> revert;
    payable(msg.sender).transfer(t.value);// no ownership check -> theft
    delete tickets[id];
}
```

### Secure
```solidity
struct Ticket { address owner; uint256 value; }
Ticket[] public tickets;

error IndexOutOfRange(uint256 index, uint256 length);
error NotTicketOwner();

function redeem(uint256 id) external {
    if (id >= tickets.length) revert IndexOutOfRange(id, tickets.length);

    Ticket storage t = tickets[id];
    if (t.owner != msg.sender) revert NotTicketOwner();

    uint256 value = t.value;   // effects
    delete tickets[id];
    (bool ok, ) = msg.sender.call{value: value}("");   // interaction last
    require(ok, "transfer failed");
}
```

## 5. Fee / Percentage Bounds

### Vulnerable
```solidity
uint256 public feeBps;   // basis points, 10_000 = 100%

function setFeeBps(uint256 bps) external onlyOwner {
    feeBps = bps;        // nothing stops bps = 50_000 (500%)
}

function takeFee(uint256 amount) internal view returns (uint256) {
    return (amount * feeBps) / 10_000;   // fee can exceed amount
}
```

### Secure
```solidity
uint256 constant BPS_DENOMINATOR = 10_000;   // 100.00%
uint256 constant MAX_FEE_BPS     = 1_000;    // cap at 10%
uint256 public   feeBps;

error FeeTooHigh(uint256 bps, uint256 max);

function setFeeBps(uint256 bps) external onlyOwner {
    if (bps > MAX_FEE_BPS) revert FeeTooHigh(bps, MAX_FEE_BPS);
    feeBps = bps;
}

function takeFee(uint256 amount) internal view returns (uint256) {
    return (amount * feeBps) / BPS_DENOMINATOR;   // bounded by construction
}
```

## 6. Untrusted Token / Target Address

### Vulnerable
```solidity
function collect(address token, address to) external {
    // token and to are attacker-chosen: arbitrary external call
    IERC20(token).transferFrom(msg.sender, to, 1e18);
}
```

### Secure
```solidity
using SafeERC20 for IERC20;

mapping(address => bool) public allowedToken;

error TokenNotAllowed(address token);
error ZeroAddress();

function addToken(address token) external onlyOwner {
    if (token == address(0)) revert ZeroAddress();
    allowedToken[token] = true;
}

function collect(address token, uint256 amount) external {
    if (!allowedToken[token]) revert TokenNotAllowed(token);   // allow-list
    if (amount == 0) revert ZeroAmount();
    // funds come to the contract, not to an arbitrary caller-chosen address
    IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
    balances[msg.sender] += amount;
}
```

## 7. Deadline and Signature Validation

### Vulnerable
```solidity
struct Order { address maker; uint256 amount; uint256 deadline; }

function fill(Order calldata o, bytes calldata sig) external {
    address signer = ECDSA.recover(keccak256(abi.encode(o)), sig);
    // signer never compared to o.maker; o.deadline never checked
    _settle(o);
}
```

### Secure
```solidity
struct Order { address maker; uint256 amount; uint256 nonce; uint256 deadline; }

mapping(address => mapping(uint256 => bool)) public usedNonce;

error Expired(uint256 deadline);
error BadSignature();

function fill(Order calldata o, bytes calldata sig) external {
    if (block.timestamp > o.deadline) revert Expired(o.deadline);

    bytes32 digest = _hashTypedDataV4(_orderHash(o));   // EIP-712
    if (ECDSA.recover(digest, sig) != o.maker) revert BadSignature();

    if (usedNonce[o.maker][o.nonce]) revert BadSignature();   // replay guard
    usedNonce[o.maker][o.nonce] = true;

    _settle(o);
}
```

## What Changed, and Why

| Validation Gap | Vulnerable | Secure |
|----------------|------------|--------|
| Zero address | Stores/sends to `address(0)` | `revert ZeroAddress()` before use |
| Amount | Any value, incl. 0 / over-balance | `> 0` and `<= balance` enforced |
| Arrays | Mismatched / unbounded loop | Equal length + `MAX_BATCH` cap |
| Index / ID | Out-of-range, no ownership | Bounds + ownership checked |
| Fee | No upper bound | Capped at `MAX_FEE_BPS` |
| Token / target | Arbitrary caller-supplied address | Allow-list + `SafeERC20` |
| Deadline / signature | Ignored / unbound signer | Expiry, signer, and nonce enforced |

## Next Steps

- **[Prevention](prevention.md)**: The full validation strategy for every input type
- **[Attack Vectors](attack-vectors.md)**: How these gaps are exploited on-chain
- **[Smart Contract Track](/learn/smart-contract)**: Continue the OWASP Smart Contract Top 10
- **[Practice](/practice)**: Fix a vulnerable contract in a hands-on challenge
