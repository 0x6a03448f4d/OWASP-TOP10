# SC07: Flash Loan Attacks - Code Examples

Each pair below shows a **vulnerable** protocol design and the **secure** version in Solidity. The theme throughout: the vulnerable version trusts a value an attacker can move with flash-borrowed capital in one transaction; the secure version does not. An illustrative **attacker contract** flow is included so you can see how the amplification is assembled.

**&#9888; EDUCATIONAL PURPOSE ONLY** — the attacker example exists so you can recognise and defend against this pattern in systems you own or are authorised to test.

## Example 1: Lending Protocol — Spot Price vs. TWAP

### Vulnerable

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPair {
    function getReserves() external view returns (uint112 base, uint112 quote, uint32);
}

contract VulnerableLending {
    IPair public pair;               // single AMM pool used as the price source
    mapping(address => uint) public collateral;   // base token deposited

    constructor(IPair _pair) { pair = _pair; }

    // BUG: price derived from the pool's CURRENT reserves = spot price.
    // A flash-funded swap can move this arbitrarily for one transaction.
    function price() public view returns (uint) {
        (uint112 base, uint112 quote, ) = pair.getReserves();
        return uint(quote) * 1e18 / uint(base);
    }

    function deposit(uint amount) external {
        collateral[msg.sender] += amount;   // (token transfer omitted for brevity)
    }

    // Attacker spikes price() with a flash swap, then borrows far more than
    // the real collateral value supports. When price snaps back, the protocol
    // is left insolvent.
    function borrow() external view returns (uint maxBorrow) {
        maxBorrow = collateral[msg.sender] * price() / 1e18;   // trusts spot price
        // ... transfer maxBorrow of the quote token to msg.sender ...
    }
}
```

### Secure

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITwapOracle {
    // Returns a time-weighted average price over `window` seconds.
    function consult(address base, uint32 window) external view returns (uint);
}

interface IAggregator {
    function latestPrice(address base) external view returns (uint);
}

contract SecureLending {
    ITwapOracle public twap;
    IAggregator public feed;         // independent, aggregated reference
    address public base;
    uint32 public constant WINDOW = 1800;   // 30-minute TWAP window
    uint public constant MAX_DEVIATION_BPS = 200;   // 2%

    mapping(address => uint) public collateral;

    constructor(ITwapOracle _twap, IAggregator _feed, address _base) {
        twap = _twap; feed = _feed; base = _base;
    }

    // FIX 1: average price over a window -> a flash loan cannot sustain the skew.
    // FIX 2: cross-check against an independent feed and reject on divergence.
    function price() public view returns (uint) {
        uint twapPrice = twap.consult(base, WINDOW);
        uint refPrice  = feed.latestPrice(base);
        uint diff = twapPrice > refPrice ? twapPrice - refPrice : refPrice - twapPrice;
        require(diff * 10_000 / refPrice <= MAX_DEVIATION_BPS, "price deviation too large");
        return twapPrice;
    }

    function deposit(uint amount) external {
        collateral[msg.sender] += amount;
    }

    function borrow() external view returns (uint maxBorrow) {
        maxBorrow = collateral[msg.sender] * price() / 1e18;   // trusts a manipulation-resistant price
    }
}
```

## Example 2: Governance — Live Balance vs. Past-Block Snapshot

### Vulnerable

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint); }

contract VulnerableGovernance {
    IERC20 public govToken;
    mapping(uint => uint) public forVotes;
    mapping(uint => bool) public executed;

    constructor(IERC20 _t) { govToken = _t; }

    // BUG: voting weight = CURRENT balance. A flash borrower holds a huge
    // balance for one transaction and that weight counts fully.
    function castVote(uint proposalId) external {
        forVotes[proposalId] += govToken.balanceOf(msg.sender);
    }

    // BUG: no timelock -> vote and execute happen in the SAME transaction,
    // so the flash-borrowed weight is still "held" at execution time.
    function execute(uint proposalId, address target, bytes calldata data) external {
        require(!executed[proposalId], "done");
        require(forVotes[proposalId] >= quorum(), "no quorum");
        executed[proposalId] = true;
        (bool ok, ) = target.call(data);   // e.g. drain the treasury
        require(ok, "exec failed");
    }

    function quorum() public pure returns (uint) { return 1_000_000e18; }
}
```

### Secure

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ERC20Votes-style token exposing historical checkpoints.
interface IVotes { function getPastVotes(address account, uint blockNumber) external view returns (uint); }

contract SecureGovernance {
    IVotes public govToken;
    uint public constant TIMELOCK = 2 days;

    struct Proposal { uint snapshotBlock; uint forVotes; uint eta; bool executed; }
    mapping(uint => Proposal) public proposals;
    mapping(uint => mapping(address => bool)) public voted;

    constructor(IVotes _t) { govToken = _t; }

    function propose(uint id) external {
        // Snapshot is a PAST block: flash-borrowed balances acquired later count for zero.
        proposals[id].snapshotBlock = block.number - 1;
    }

    // FIX 1: weight from a past-block snapshot -> flash balance = 0 votes.
    function castVote(uint id) external {
        Proposal storage p = proposals[id];
        require(!voted[id][msg.sender], "voted");
        voted[id][msg.sender] = true;
        p.forVotes += govToken.getPastVotes(msg.sender, p.snapshotBlock);
    }

    function queue(uint id) external {
        Proposal storage p = proposals[id];
        require(p.forVotes >= quorum(), "no quorum");
        p.eta = block.timestamp + TIMELOCK;   // FIX 2: delay execution
    }

    // Execution can only happen in a LATER transaction, after the timelock.
    function execute(uint id, address target, bytes calldata data) external {
        Proposal storage p = proposals[id];
        require(p.eta != 0 && block.timestamp >= p.eta, "timelocked");
        require(!p.executed, "done");
        p.executed = true;
        (bool ok, ) = target.call(data);
        require(ok, "exec failed");
    }

    function quorum() public pure returns (uint) { return 1_000_000e18; }
}
```

## Example 3: Vault — Manipulable Share Price vs. Hardened Accounting

### Vulnerable

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 { function balanceOf(address) external view returns (uint); }

contract VulnerableVault {
    IERC20 public asset;
    uint public totalShares;
    mapping(address => uint) public shares;

    constructor(IERC20 _a) { asset = _a; }

    // BUG: share price derived from live token balance of the vault.
    // A flash "donation" straight to the vault inflates the price so the
    // first-depositor's single share captures later deposits (rounding to 0).
    function sharePrice() public view returns (uint) {
        if (totalShares == 0) return 1e18;
        return asset.balanceOf(address(this)) * 1e18 / totalShares;   // gameable
    }

    function deposit(uint assets) external returns (uint minted) {
        minted = assets * 1e18 / sharePrice();   // rounds DOWN -> can round to 0
        shares[msg.sender] += minted;
        totalShares += minted;
    }
}
```

### Secure

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SecureVault {
    uint public totalShares;
    uint public totalAssets;                 // FIX: internal accounting, not balanceOf
    uint constant MINIMUM_LIQUIDITY = 1e3;   // FIX: dead shares defeat first-depositor inflation
    mapping(address => uint) public shares;

    constructor() {
        // Seed unredeemable shares so the pool can never start from an empty,
        // manipulable state.
        totalShares = MINIMUM_LIQUIDITY;
        shares[address(0xdEaD)] = MINIMUM_LIQUIDITY;
    }

    // FIX: price from tracked accounting; a raw token donation does NOT move it.
    function sharePrice() public view returns (uint) {
        return totalAssets == 0 ? 1e18 : totalAssets * 1e18 / totalShares;
    }

    function deposit(uint assets) external returns (uint minted) {
        require(assets > 0, "zero");
        minted = assets * totalShares / (totalAssets == 0 ? 1 : totalAssets);
        require(minted > 0, "shares round to zero");   // FIX: reject dust-rounding griefing
        shares[msg.sender] += minted;
        totalShares += minted;
        totalAssets += assets;               // credited only via the accounted path
        // ... pull `assets` from msg.sender via transferFrom ...
    }
}
```

## Example 4: The Attacker Contract (Illustrative Flow)

This is the shape of the single contract that weaponises the vulnerable lending design from Example 1. It borrows, manipulates, extracts, and repays—all in one atomic callback. If the run is not profitable, the whole transaction reverts and the attacker loses only gas.

```
// SPDX-License-Identifier: MIT
// EDUCATIONAL: shows how flash capital amplifies a spot-price bug.
pragma solidity ^0.8.20;

interface IFlashLender { function flashLoan(address token, uint amount, bytes calldata) external; }
interface IPair { function swap(uint amountOut, address to, bytes calldata) external; }
interface IVulnerableLending { function deposit(uint) external; function borrow() external returns (uint); }
interface IERC20 { function transfer(address,uint) external returns (bool); function approve(address,uint) external returns (bool); function balanceOf(address) external view returns (uint); }

contract FlashAttacker {
    IFlashLender  public lender;
    IPair         public pair;
    IVulnerableLending public victim;
    IERC20        public base;
    address       public owner;

    constructor(address _lender, address _pair, address _victim, address _base) {
        lender = IFlashLender(_lender);
        pair   = IPair(_pair);
        victim = IVulnerableLending(_victim);
        base   = IERC20(_base);
        owner  = msg.sender;
    }

    // Step 0: launch the atomic attack.
    function attack(uint amount) external {
        require(msg.sender == owner, "not owner");
        lender.flashLoan(address(base), amount, "");   // lender calls onFlashLoan()
    }

    // Step 1-4 all run here, inside ONE transaction, with borrowed funds present.
    function onFlashLoan(address token, uint amount, uint fee) external {
        require(msg.sender == address(lender), "only lender");

        // 1) MANIPULATE: dump the borrowed base into the pool -> base price spikes/crashes
        base.approve(address(pair), amount);
        pair.swap(/* skew reserves */ 0, address(this), "");

        // 2) EXTRACT: interact with the victim while its spot price is wrong
        victim.deposit(base.balanceOf(address(this)));
        uint borrowed = victim.borrow();   // over-borrows against the fake price

        // 3) UNWIND: reverse the swap to restore the pool (omitted for brevity)

        // 4) REPAY: return principal + fee; surplus remains as profit.
        //    If balance < amount + fee, the ENTIRE transaction reverts here.
        base.transfer(address(lender), amount + fee);
        borrowed;  // silence unused warning; borrowed funds are the profit source
    }

    // Step 5: sweep profit after a successful run.
    function withdraw(address t) external {
        require(msg.sender == owner, "not owner");
        IERC20(t).transfer(owner, IERC20(t).balanceOf(address(this)));
    }
}
```

**Why the secure designs defeat this**: against `SecureLending`, step 1 cannot move a 30-minute TWAP within one transaction, and the deviation check reverts on an impossible swing—so step 2 never over-borrows and the transaction reverts unprofitably. The attacker is left with only a gas bill.

## What Changed, and Why

| Weakness | Vulnerable | Secure |
| --- | --- | --- |
| Price source | Single-pool spot price (`getReserves`) | TWAP + independent feed + deviation bound |
| Vote weight | Live `balanceOf` at vote time | `getPastVotes` from a past-block snapshot |
| Execution timing | Vote and execute in one transaction | Timelock forces execution to a later transaction |
| Share price | Derived from live `balanceOf(this)` | Internal accounting + dead shares, reject dust rounding |
| Net effect on attacker | Risk-free drain | Manipulation reverts; attacker loses only gas |

## Next Steps

- **Prevention**: The full defence strategy—design for infinite one-tx capital
- **Attack Vectors**: How these exploits are assembled and chained
- **Smart Contract Learning Path**: Continue the OWASP Smart Contract Top 10
- **Practice**: Apply what you've learned in hands-on challenges
