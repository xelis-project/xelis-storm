## XELIS Storm

XELIS Storm is a stress-test tool used on testnet for spamming easily transactions from differents wallets, with differents transfers count per TX.

## Usage

Please note that XELIS Storm is not connecting to an existing wallet over RPC. It is actually creating `n` wallets and manage them directly!
This ensure better efficiency, smaller overhead (such as precomputed tables, RPC connections as those are shared across wallets) and no RPC server needed.

Each wallet in `wallets` will be reused by default.

To start, when those new wallets are created, send them some `XEL` to start the spamming. This is required to pay the TX fees.

- Configure many transfers per TX you want using `--fixed-transfers-count` (default to random: between 1 and 255).
- Configure from how many wallets you want to generate transactions using `--from-n-wallets` (default to 1).
- By default, each wallet send to another wallet used for spamming OR from a newly generated address (if only 1 wallet started).
- If you want to redirect all transactions to one specific address, use `--fixed-transfer-receiver-address`.

Build it using `cargo build --release` or run it directly using `cargo run --release -- <your launch options>`

To see all the configuration available, use `--help`.