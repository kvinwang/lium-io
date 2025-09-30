# Local Testnet Setup

This directory holds docker-compose stacks for a local miner and a mock
validator (with a web UI) that target your executor at `50.145.48.92`.

- `miner/`: central miner stack (Postgres + miner + connector). Provides helper
  script to seed the validator/executor mapping.
- `validator/`: FastAPI app with a web UI that authenticates with the miner and
  submits SSH keys. Generated keys and executor connection details land under
  `validator/ssh-keys`.
- `wallets/`: shared wallet directory mounted by both stacks. Create your
  Bittensor wallet and hotkeys here before starting the services.

Workflow:
1. Create the shared docker network: `docker network create lium-testnet`
2. Run `./testnet/scripts/generate_wallets.sh` once to create wallets and update
   env files
3. Configure and start the miner stack (`testnet/miner`)
4. Seed the miner database with the validator + executor using the provided
   script
5. Configure and run the mock validator UI (`testnet/validator`) and browse to
   its exposed port (defaults to `http://localhost:28080`)

Check each README for detailed instructions.
