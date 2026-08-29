# SC09: Insecure Randomness - Code Examples

These paired examples show **vulnerable** on-chain randomness next to a **secure** alternative. The pattern to internalise is always the same: randomness that any actor can compute, observe, or bias within the transaction that consumes it is not randomness at all. Each secure version imports unpredictability from outside that transaction — a verifiable oracle or a prior commitment.

> Every Solidity snippet below is illustrative and trimmed for clarity (imports, access control, and error handling are abbreviated). Do not copy the vulnerable versions into production; they exist to be understood and rejected.

## On This Page

- [Example 1: Lottery Winner Selection](#example-1-lottery-winner-selection)
- [Example 2: NFT Rarity / Mint](#example-2-nft-rarity--mint)
- [Example 3: Naive keccak256 vs. Commit-Reveal](#example-3-naive-keccak256-vs-commit-reveal)
- [Example 4: The Compute-Then-Revert Attacker](#example-4-the-compute-then-revert-attacker)
- [What Changed / Why Secure](#what-changed--why-secure)
- [Real Incident Classes](#real-incident-classes)

## Example 1: Lottery Winner Selection

A lottery pays the whole pot to one player. If the winning index is derived from block variables, the value is either public before the transaction lands or set by the block proposer — so it can be predicted or biased.

### Vulnerable: block variables pick the winner

```solidity
// VULNERABLE -- winner is computable from public block data
contract LotteryVulnerable {
    address[] public players;

    function enter() external payable {
        require(msg.value == 0.1 ether, "fixed entry");
        players.push(msg.sender);
    }

    function drawWinner() external {
        // Every input here is public or proposer-controlled in this same block.
        uint256 rand = uint256(keccak256(abi.encodePacked(
            block.timestamp,
            blockhash(block.number - 1),
            block.prevrandao
        )));
        uint256 winnerIndex = rand % players.length;   // predictable
        payable(players[winnerIndex]).transfer(address(this).balance);
        delete players;
    }
}
```

**Why it breaks:** a caller can evaluate the exact same expression in their own contract in the same transaction, learn `winnerIndex` before entering or drawing, and act only when it points at them. The block proposer can additionally nudge `block.timestamp` or `block.prevrandao` to steer the result.

### Secure: Chainlink VRF (request/fulfil with proof)

```solidity
// SECURE -- randomness arrives in a later tx, carrying an on-chain proof
import {VRFConsumerBaseV2} from "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
import {VRFCoordinatorV2Interface} from "@chainlink/contracts/src/v0.8/interfaces/VRFCoordinatorV2Interface.sol";

contract LotterySecure is VRFConsumerBaseV2 {
    VRFCoordinatorV2Interface immutable COORDINATOR;
    uint64  immutable subId;
    bytes32 immutable keyHash;
    uint16  constant CONFIRMATIONS = 3;
    uint32  constant CALLBACK_GAS  = 200000;
    uint32  constant NUM_WORDS     = 1;

    address[] public players;
    mapping(uint256 => bool) public pending;   // requestId -> awaiting fulfil

    // 1) REQUEST -- no usable randomness exists in this transaction
    function drawWinner() external returns (uint256 requestId) {
        requestId = COORDINATOR.requestRandomWords(
            keyHash, subId, CONFIRMATIONS, CALLBACK_GAS, NUM_WORDS);
        pending[requestId] = true;
    }

    // 2) FULFIL -- coordinator calls back ONLY after verifying the VRF proof
    function fulfillRandomWords(uint256 requestId, uint256[] memory words)
        internal override
    {
        require(pending[requestId], "unknown request");
        pending[requestId] = false;
        uint256 winnerIndex = words[0] % players.length;   // proven random
        payable(players[winnerIndex]).transfer(address(this).balance);
        delete players;
    }
}
```

The winning value does not exist when `drawWinner()` runs, so no one can compute-then-revert; the coordinator accepts only a word whose proof verifies against the registered key, so it cannot be cherry-picked.

## Example 2: NFT Rarity / Mint

Rarity assignment is high value: a rare trait can be worth many times the mint price, so any predictability is quickly and profitably exploited by mint bots.

### Vulnerable: rarity from block data at mint time

```solidity
// VULNERABLE -- rarity is derivable in the same tx as the mint
contract RarityVulnerable {
    uint256 public nextId;

    function mint() external payable returns (uint256 id) {
        require(msg.value == 0.05 ether, "mint price");
        id = nextId++;
        uint256 roll = uint256(keccak256(abi.encodePacked(
            block.timestamp, block.prevrandao, msg.sender, id
        ))) % 1000;
        // roll < 10 == legendary. An attacker computes roll BEFORE minting
        // and only submits the tx when it lands on a rare tier.
        _assignRarity(id, roll);
    }
}
```

**Why it breaks:** a bot contract reproduces the same `roll` expression, mints only when the result is rare, and reverts otherwise — draining every valuable trait for the cost of gas on winning attempts.

### Secure: reveal rarity from VRF after mint

```solidity
// SECURE -- mint first, assign rarity later from proven randomness
contract RaritySecure is VRFConsumerBaseV2 {
    // ... COORDINATOR / keyHash / subId as in Example 1 ...
    uint256 public nextId;
    mapping(uint256 => uint256) public requestToTokenId;
    mapping(uint256 => uint256) public rarityOf;   // 0 == not yet revealed

    // 1) Mint issues the token with NO rarity known yet
    function mint() external payable returns (uint256 id) {
        require(msg.value == 0.05 ether, "mint price");
        id = nextId++;
        uint256 requestId = COORDINATOR.requestRandomWords(
            keyHash, subId, 3, 200000, 1);
        requestToTokenId[requestId] = id;
    }

    // 2) Rarity is set in a later tx from a proof-verified word
    function fulfillRandomWords(uint256 requestId, uint256[] memory words)
        internal override
    {
        uint256 id = requestToTokenId[requestId];
        rarityOf[id] = (words[0] % 1000) + 1;   // proven; not gameable at mint
    }
}
```

Because rarity is unknown at mint time and only fixed later from a verified word, there is no value to predict and nothing to selectively revert against.

## Example 3: Naive keccak256 vs. Commit-Reveal

When an external oracle is genuinely unavailable, a hardened **commit-reveal** scheme can import unpredictability from a commitment made *before* the outcome data existed. Hashing public block variables cannot.

### Vulnerable: "random" from keccak256(block.*)

```solidity
// VULNERABLE -- a deterministic hash of public inputs is still public
contract CoinFlipVulnerable {
    function flip(bool guess) external returns (bool won) {
        bool outcome = uint256(keccak256(abi.encodePacked(
            block.timestamp, blockhash(block.number - 1)
        ))) % 2 == 0;
        won = (guess == outcome);   // attacker precomputes outcome, always "wins"
        if (won) payable(msg.sender).transfer(1 ether);
    }
}
```

### Secure: commit-reveal with deposit, slashing, and timeout

```solidity
// SECURE -- entropy is committed before the outcome-determining data exists
contract CommitRevealFlip {
    struct Entry { bytes32 commitment; uint256 deposit; bool revealed; }
    mapping(address => Entry) public entries;
    uint256 public commitDeadline;
    uint256 public revealDeadline;
    bytes32 public seedAccumulator;
    uint256 constant DEPOSIT = 0.1 ether;

    // COMMIT: lock hash of (secret, salt) plus a slashable deposit
    function commit(bytes32 commitment) external payable {
        require(block.timestamp < commitDeadline, "commit closed");
        require(msg.value == DEPOSIT, "bad deposit");
        entries[msg.sender] = Entry(commitment, msg.value, false);
    }

    // REVEAL: prove preimage; mix EVERY secret into the shared seed
    function reveal(uint256 secret, bytes32 salt) external {
        require(block.timestamp >= commitDeadline
             && block.timestamp < revealDeadline, "not reveal phase");
        Entry storage e = entries[msg.sender];
        require(!e.revealed, "already revealed");
        require(keccak256(abi.encodePacked(secret, salt)) == e.commitment, "bad reveal");
        e.revealed = true;
        seedAccumulator = keccak256(abi.encodePacked(seedAccumulator, secret));
        payable(msg.sender).transfer(e.deposit);   // returned on honest reveal
    }

    // Unrevealed deposits are FORFEIT after revealDeadline, removing the
    // incentive to withhold an unfavourable secret.
}
```

**Two failure modes a naive commit-reveal must close:**

- **Reveal withholding:** the last participant sees the accumulating seed and, if their reveal would produce a losing outcome, simply never reveals. Defence: slash the unrevealed deposit so withholding costs more than it saves, and mix *all* revealed secrets so one holdout cannot single-handedly steer the result.
- **Reveal front-running:** an observer watching the mempool copies a broadcast reveal and submits their own tuned reveal first. Defence: separate commit and reveal phases in time, bind each reveal to a deposit committed earlier, and never let a late entrant join after reveals begin.

> Commit-reveal without deposits, slashing, and a timeout fallback is *gameable*. The scheme only holds when withholding or reordering a reveal is provably more expensive than any advantage it buys.

## Example 4: The Compute-Then-Revert Attacker

This is the exploit that defeats every "hash the block variables" design. Because the RNG expression is deterministic and all its inputs are visible in the current transaction, an attacker contract simply **reproduces the same expression**, checks whether it would win, and reverts otherwise — so the only transactions that ever land are winning ones.

### Vulnerable target

```solidity
// VULNERABLE target -- deterministic RNG from same-tx public inputs
contract GuessGameVulnerable {
    function play() external payable returns (bool won) {
        require(msg.value == 1 ether, "stake");
        uint256 rand = uint256(keccak256(abi.encodePacked(
            block.timestamp, blockhash(block.number - 1), address(this)
        ))) % 10;
        won = (rand == 7);
        if (won) payable(msg.sender).transfer(2 ether);
    }
}
```

### Attacker: only enters in the same tx when it already knows it wins

```solidity
// ATTACKER -- recomputes the target's RNG and reverts on a loss
interface IGuessGame { function play() external payable returns (bool); }

contract Attacker {
    IGuessGame immutable game;
    constructor(address _game) { game = IGuessGame(_game); }

    function attack() external payable {
        // Reproduce the EXACT expression the target will evaluate this block.
        uint256 rand = uint256(keccak256(abi.encodePacked(
            block.timestamp, blockhash(block.number - 1), address(game)
        ))) % 10;

        // Abort before spending the stake unless it is a guaranteed win.
        require(rand == 7, "not a winning block -- revert, pay only gas");

        game.play{value: 1 ether}();   // executes only when the win is certain
    }
    // With unlimited, free retries the attacker eventually hits a winning
    // block and drains the prize pool. The secure fix is Example 1/2: make the
    // randomness unavailable in the transaction that consumes it (VRF split),
    // so there is no value to recompute and nothing to revert against.
}
```

**The structural lesson:** defences like "reject contract callers" (`require(msg.sender == tx.origin)`) are trivially bypassed and break composability. The only reliable fix is to split request from consumption so the outcome does not exist when the caller acts — exactly what the VRF request/fulfil pattern provides.

## What Changed / Why Secure

| Example | Vulnerable source of randomness | Secure fix | Why the fix holds |
|---------|--------------------------------|------------|-------------------|
| 1. Lottery | `keccak256(block.timestamp, blockhash, prevrandao)` | Chainlink VRF request/fulfil | Value does not exist at request time; proof verified on-chain |
| 2. NFT rarity | Block data hashed at mint | Mint now, assign rarity later from VRF | Nothing to predict at mint; rarity fixed from a proven word |
| 3. Coin flip | `keccak256(block.*)` deterministic hash | Commit-reveal + deposit, slashing, timeout | Entropy committed before outcome data existed; withholding is slashed |
| 4. Guess game | Same-tx deterministic RNG | Split request from consumption (VRF) | No same-tx value to recompute; compute-then-revert is defeated |

## Real Incident Classes

The failures below are recurring *classes* of real-world exploits, not specific named events. Each maps directly to one of the examples above.

| Incident class | Root cause | Maps to |
|----------------|-----------|---------|
| Predictable-RNG lotteries drained by a precomputing caller | Winner index from block variables, computable in the same tx | Examples 1, 4 |
| On-chain casino / dice games farmed for guaranteed wins | Deterministic hash of public inputs; free retries via revert | Examples 3, 4 |
| NFT mints where bots harvested every rare trait | Rarity derived from block data known before minting | Example 2 |
| Proposer-biased draws | Reliance on `timestamp` / `prevrandao` a block proposer can nudge | Examples 1, 2 |
| Commit-reveal games gamed by reveal withholding | No deposit / slashing / timeout on non-reveal | Example 3 |

## Next Steps

- **[Overview](overview.html)**: What insecure randomness is and why on-chain secrecy is impossible
- **[Attack Vectors](attack-vectors.html)**: The prediction, proposer-bias, and compute-then-revert techniques in depth
- **[Prevention](prevention.html)**: The full checklist for VRF, commit-reveal, and request/consumption separation
- **[Smart Contract Learning Path](/learn/smart-contract)**: Continue the Smart Contract Top 10
- **[Practice](/practice)**: Harden a vulnerable RNG contract in a guided challenge
