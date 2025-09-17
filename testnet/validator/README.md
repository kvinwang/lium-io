# Mock Validator Stack

This stack now includes a tiny FastAPI application that exposes a web console for
submitting renting requests to the local miner and inspecting the executor
response.

## Configure

1. Ensure the shared docker network exists (see `../miner/README.md`).
2. Update `.env`:
   - `BITTENSOR_WALLET_NAME` / `BITTENSOR_WALLET_HOTKEY_NAME`: the wallet that owns
the validator hotkey. The corresponding keys must live under `../wallets`.
   - `TARGET_MINER_HOTKEY`: SS58 address for the miner hotkey you seeded in the
     miner database.
   - `VALIDATOR_HOTKEY_SS58`: the validator hotkey address used to authenticate to
     the miner.
   - `MINER_HOST` / `MINER_PORT`: leave as `miner:18080` if you followed the local
     stack defaults; adjust if you expose the miner differently.
   - `TARGET_EXECUTOR_ID`: optional UUID to target a single executor; leave blank to
     broadcast to every executor the miner returns.
   - `WEB_EXTERNAL_PORT`: host port for the UI (default `28080`).

## Run the mock validator UI

```bash
cd testnet/validator
docker compose up --build
```

Navigate to `http://localhost:28080` (replace with your chosen external port).
The page lets you:

- Launch a renting request (optionally for a specific executor UUID).
- Watch live status updates while the validator authenticates and waits for
  `AcceptSSHKeyRequest`.
- Click **Open Terminal** next to any executor to establish a browser-based SSH
  session. Commands typed into the prompt are executed on the executor in real
  time.
- Download the raw accept payload via `http://localhost:28080/accept`.
- Inspect the generated SSH keys in `./ssh-keys`.

Re-run `docker compose up --build` whenever you want to restart the UI, or
`docker compose down` to stop it.
