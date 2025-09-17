# Testnet Miner Stack

This folder provides a lightweight docker-compose stack for running the compute
subnet miner locally while targeting your remote executor at `50.145.48.92`.

## Prerequisites

1. Create a shared docker network once (both stacks join it):
   ```bash
docker network create testnet-net
   ```
2. Prepare a Bittensor wallet directory that both the miner and the mock
   validator will mount. The default path `../wallets` is already volume-mapped.

## Configure the miner

1. Copy `.env` and fill in the blanks:
   - Generate (or import) a wallet and hotkey for the miner.
   - Set `MINER_HOTKEY_SS58` to the miner hotkey address.
   - Set `TESTNET_VALIDATOR_HOTKEY` to the validator hotkey that the mock
     validator will use.
   - Adjust `TESTNET_EXECUTOR_*` if your executor details change.

2. Create the wallets (one-time). The helper script generates both miner and
   validator hotkeys, updates the `.env` files with their SS58 addresses, and
   prints the wallet summary:
   ```bash
./testnet/scripts/generate_wallets.sh
   ```
   If you prefer manual control, run the btcli commands from within the miner
   container as documented previously.

3. (Optional) Retrieve the SS58 addresses manually if you skipped the helper
   script:
   ```bash
docker compose run --rm miner pdm run btcli wallet overview --wallet.name ${BITTENSOR_WALLET_NAME}
   ```

## Start the stack

```bash
cd testnet/miner
docker compose up -d
```

After the containers apply database migrations, add the validator and executor
rows so the miner accepts the mock validator and forwards SSH keys to your
remote executor. The helper reads defaults from `.env` (for example,
`TESTNET_EXECUTOR_PRICE_PER_HOUR`), so you can omit those values if they match:

```bash
./testnet/scripts/miner-cli.sh add 50.145.48.92 21020 0.0
```

You can rerun the helper script whenever you update the inputs; existing rows
are updated in-place.

## Useful commands

- Tail miner logs: `docker compose logs -f miner`
- Stop the stack: `docker compose down`
- Reset Postgres volume: `docker compose down -v` (removes database contents)
- Trigger a renting flow from the UI: visit the mock validator at
  `http://localhost:28080` after starting the validator stack.

The mock validator stack expects the miner service to be reachable at the
network alias `miner` on `${INTERNAL_PORT}`.
