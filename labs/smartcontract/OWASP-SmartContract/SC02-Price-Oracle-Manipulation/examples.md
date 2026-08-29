# SC02: Price Oracle Manipulation - Code Examples

Each pair below shows a **vulnerable** Solidity pattern and the **secure** version for the same job. The theme throughout: a spot price read from a DEX pool is attacker-controllable, while a checked decentralized feed or a time-weighted average is not.

> **⚠️ EDUCATIONAL PURPOSE ONLY** — snippets are illustrative and trimmed for clarity. Use audited oracle libraries and full test coverage in production.

## Example 1: Lending Collateral Price

### Vulnerable
```solidity
// Prices collateral from one Uniswap V2 pool's spot reserves.
// A flash-loaned swap moves the reserves in the same tx -> over-borrow.
interface IUniswapV2Pair {
    function getReserves() external view returns (uint112, uint112, uint32);
}

contract LendingVulnerable {
    IUniswapV2Pair public pair;   // WETH / TOKEN pool

    function collateralValue(uint256 tokenAmount) public view returns (uint256) {
        (uint112 reserveWeth, uint112 reserveToken, ) = pair.getReserves();
        uint256 price = uint256(reserveWeth) * 1e18 / uint256(reserveToken);
        return tokenAmount * price / 1e18;   // spot price = attacker-controlled
    }

    function borrow(uint256 tokenCollateral, uint256 borrowAmount) external {
        require(borrowAmount <= collateralValue(tokenCollateral), "under-collateralized");
        // ... transfer collateral in, send borrowAmount out ...
    }
}
```

### Secure
```solidity
// Prices collateral from a Chainlink feed with freshness + sign checks.
// No single on-chain pool can move an aggregated decentralized feed.
interface AggregatorV3Interface {
    function latestRoundData() external view returns (
        uint80 roundId, int256 answer, uint256 startedAt,
        uint256 updatedAt, uint80 answeredInRound);
    function decimals() external view returns (uint8);
}

contract LendingSecure {
    AggregatorV3Interface public feed;      // TOKEN / USD feed
    uint256 public constant MAX_STALENESS = 1 hours;

    function _price() internal view returns (uint256) {
        (uint80 roundId, int256 answer, , uint256 updatedAt, uint80 answeredInRound)
            = feed.latestRoundData();
        require(answer > 0, "bad price");
        require(answeredInRound >= roundId, "stale round");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale price");
        return uint256(answer);             // scaled by feed.decimals()
    }

    function collateralValue(uint256 tokenAmount) public view returns (uint256) {
        return tokenAmount * _price() / (10 ** feed.decimals());
    }

    function borrow(uint256 tokenCollateral, uint256 borrowAmount) external {
        require(borrowAmount <= collateralValue(tokenCollateral), "under-collateralized");
        // ... transfer collateral in, send borrowAmount out ...
    }
}
```

## Example 2: `getAmountsOut` vs. TWAP

### Vulnerable
```solidity
// Uses the router's spot quote as a "price". Same movable reserves,
// friendlier name — a flash loan sets the quote to whatever it wants.
interface IUniswapV2Router {
    function getAmountsOut(uint256 amountIn, address[] calldata path)
        external view returns (uint256[] memory);
}

contract QuoteVulnerable {
    IUniswapV2Router public router;
    address[] public path;   // [TOKEN, USDC]

    function priceOfToken() public view returns (uint256) {
        uint256[] memory out = router.getAmountsOut(1e18, path);
        return out[out.length - 1];   // instantaneous, manipulable
    }
}
```

### Secure
```solidity
// Reads a Uniswap V3 TWAP over a window. To move a 30-min average,
// an attacker must hold the manipulation for many blocks — expensive, visible.
interface IUniswapV3Pool {
    function observe(uint32[] calldata secondsAgos)
        external view returns (int56[] memory tickCumulatives, uint160[] memory);
}

contract TwapSecure {
    IUniswapV3Pool public pool;
    uint32 public constant WINDOW = 1800;   // 30 minutes

    function averageTick() public view returns (int24) {
        uint32[] memory ago = new uint32[](2);
        ago[0] = WINDOW; ago[1] = 0;
        (int56[] memory cum, ) = pool.observe(ago);
        int56 delta = cum[1] - cum[0];
        int24 avgTick = int24(delta / int56(uint56(WINDOW)));
        if (delta < 0 && (delta % int56(uint56(WINDOW)) != 0)) avgTick--;  // round toward -inf
        return avgTick;
        // convert avgTick -> price via OracleLibrary.getQuoteAtTick(...)
    }
}
```

## Example 3: LP-Token / `balanceOf` Valuation

### Vulnerable
```solidity
// Values a share by the pool's live balance. A donation or flash-loaned
// swap inflates balanceOf, so mint/redeem happen at a fake price.
contract VaultVulnerable {
    IERC20 public asset;
    uint256 public totalShares;

    function pricePerShare() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return asset.balanceOf(address(this)) * 1e18 / totalShares;  // manipulable
    }

    function redeem(uint256 shares) external returns (uint256 amount) {
        amount = shares * pricePerShare() / 1e18;   // attacker inflates first
        totalShares -= shares;
        asset.transfer(msg.sender, amount);
    }
}
```

### Secure
```solidity
// Tracks accounted assets internally instead of reading raw balanceOf,
// so a direct transfer/donation cannot change the share price.
contract VaultSecure {
    IERC20 public asset;
    uint256 public totalShares;
    uint256 public totalAssets;     // updated only on real deposits/withdrawals

    function pricePerShare() public view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return totalAssets * 1e18 / totalShares;   // not tied to balanceOf
    }

    function redeem(uint256 shares) external returns (uint256 amount) {
        amount = shares * pricePerShare() / 1e18;
        totalShares -= shares;
        totalAssets -= amount;                     // internal accounting
        asset.transfer(msg.sender, amount);
    }
    // For LP-token collateral, price the underlyings from checked feeds and
    // derive "fair reserves" from the pool invariant — never live balances.
}
```

## Example 4: Single Source vs. Cross-Checked Sources

### Vulnerable
```solidity
// One source, believed blindly. Manipulate that one venue and you win.
contract SingleSource {
    IUniswapV2Pair public pair;

    function price() public view returns (uint256) {
        (uint112 r0, uint112 r1, ) = pair.getReserves();
        return uint256(r1) * 1e18 / uint256(r0);   // no cross-check, no bound
    }
}
```

### Secure
```solidity
// Cross-checks a decentralized feed against an on-chain TWAP and refuses
// to return a price when the two disagree beyond a bound (fail closed).
contract MultiSource {
    uint256 public constant MAX_DEVIATION_BPS = 200;   // 2%

    function feedPrice() public view returns (uint256) { /* checked Chainlink read */ }
    function twapPrice() public view returns (uint256) { /* V3 TWAP, section above */ }

    function safePrice() public view returns (uint256) {
        uint256 a = feedPrice();
        uint256 b = twapPrice();
        uint256 diff = a > b ? a - b : b - a;
        require(diff * 10_000 / a <= MAX_DEVIATION_BPS, "oracle divergence");
        return a;   // both sources agree -> safe to act on
    }
}
```

## Example 5: Adding Deviation Bounds and a Circuit Breaker

### Vulnerable
```solidity
// Acts on any price, no matter how implausible the jump.
contract UnboundedAction {
    function liquidate(address position, uint256 price) external {
        if (isUnderwater(position, price)) {   // price used with no sanity check
            _seizeCollateral(position);        // a nudged price force-liquidates
        }
    }
}
```

### Secure
```solidity
// Rejects implausible moves, enforces a range, and can be paused.
contract BoundedAction {
    uint256 public lastGoodPrice;
    bool public paused;
    uint256 constant MAX_MOVE_BPS = 1000;    // 10% per update
    uint256 constant FLOOR = 1e6;
    uint256 constant CEIL  = 1e12;

    modifier notPaused() { require(!paused, "paused"); _; }

    function _check(uint256 candidate) internal view returns (uint256) {
        require(candidate >= FLOOR && candidate <= CEIL, "out of range");
        uint256 move = candidate > lastGoodPrice ? candidate - lastGoodPrice
                                                 : lastGoodPrice - candidate;
        require(move * 10_000 / lastGoodPrice <= MAX_MOVE_BPS, "implausible jump");
        return candidate;
    }

    function liquidate(address position, uint256 price) external notPaused {
        uint256 safe = _check(price);
        if (isUnderwater(position, safe)) _seizeCollateral(position);
    }
}
```

## What Changed, and Why

| Weakness | Vulnerable | Secure |
| --- | --- | --- |
| Price source | Spot `getReserves` / `getAmountsOut` | Checked decentralized feed and/or TWAP |
| Freshness | `updatedAt` ignored | Staleness and round-completeness enforced |
| Share/LP valuation | `balanceOf` / live reserves | Internal accounting / fair-value formula |
| Number of sources | Single, believed blindly | Multiple, cross-checked with deviation bound |
| Action safety | Acts on any price | Sanity bounds + circuit breaker + rate limits |

## Next Steps

- **[Prevention](prevention.md)**: The full manipulation-resistant pricing strategy
- **[Attack Vectors](attack-vectors.md)**: How these spot reads are exploited atomically
- **[Smart Contract Top 10](/learn/smart-contract)**: Return to the full lesson index
- **[Practice](/practice)**: Apply what you've learned in hands-on challenges
