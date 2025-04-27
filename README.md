# Decentralized Blockchain Voting Platform
A peer-to-peer, Proof‑of‑Work voting system built in Python, designed to turn standard operating procedures into secure, verifiable, and fully automated elections.

It leverages ECDSA public/private key cryptography for vote signing, a two-phase prepare/commit consensus over a configurable-difficulty PoW chain, and UDP multicast for dynamic peer discovery—all exposed through a clean Flask REST API and an easy-to-use CLI.

## Blockchain Voting Demo using 6 nodes
https://github.com/user-attachments/assets/adc68fd5-8e6c-4020-8cf1-68662f521c20

## Key Features
+ Secure Voting: Each vote is signed client-side with ECDSA keys and protected against replay attacks using nonces and timestamps.
+ Proof‑of‑Work & Consensus: Configurable mining difficulty with a majority‑quorum (≥50%) two‑phase prepare/commit protocol and automatic rollback on failure.
+ P2P Discovery: Automatic LAN peer-discovery via UDP multicast, with thread-safe node list management.
+ REST API & CLI: Full set of endpoints (**/register_node**, **/vote**, **/mine**, **/sync**, **/results**, **/metrics**, **/healthz**, etc.) and a companion **cli.py** for one-command operations.

## Prerequisites
+ Python 3.10+
+ Install dependencies:`pip install -r requirements.txt`

## Source Code Architecture
```
├── blockchain.py      Core blockchain data structures
├── api.py             Flask endpoints
├── cli.py             Command-line interface wrapping REST API calls into user-friendly commands
├── config.py          Centralized constants for easy customization
├── p2p.py             UDP multicast-based peer discovery   
```
## Implementation Breakdown
### #1 Peer Discovery
+ Uses UDP multicast to periodically broadcast the node’s IP and HTTP port on a well-known group and port.
+ A background listener joins the multicast group, parses incoming announcements, filters out duplicates, and adds new peers to the in-memory `blockchain.nodes` list under a thread lock.
### #2 Blockchain Core
+ Defines `Block` and `Blockchain` classes: each block contains an index, timestamp, list of signed votes, proof (nonce), and a SHA-256 hash linking to its predecessor.
+ Performs a proof-of-work loop against the `difficulty` target, then initiates a two-phase prepare/commit consensus:
  + **Prepare**: propose the new block to peers, requiring ≥50% acknowledgments before proceeding.
  + **Commit**: broadcast the commit command to append the block upon majority approval, with automatic rollback if quorum isn’t met.
+ Includes chain validation and conflict resolution by fetching peer chains and selecting the longest valid chain, ensuring eventual consistency
### #3 API Layer
+ Implements a full Flask application exposing endpoints for all operations:
  + **Node management**: `/register_node`, `/peers/register` for cluster membership.
  + **Voting flow**: `/vote`, `/transactions/new` with signature verification and nonce/timestamp checks.
  + **Consensus actions**: `/mine`, `/block/prepare`, `/block/commit`, `/sync` for mining and reconciling state.
  + **Operational utilities**: `/metrics`, `/healthz`, `/help`.
  + Wraps peer broadcasts in `broadcast_post/broadcast_get` helpers that skip the originator and snapshot `blockchain.nodes` under a lock for thread safety.
### #4 CLI Interface
+ Provides commands (`genkey`, `register`, `vote`, `mine`) that mirror API endpoints, abstracting HTTP calls and JSON parsing.
+ Manages key-pair generation with optional passphrase encryption, public key extraction to hex format, and secure private key loading.
+ Simplifies workflows so end users can register nodes, cast votes, and mine blocks with single commands without dealing with raw HTTP or cryptographic details.
### #5 Configuration
+ Centralized tunable parameters: candidate list, mining difficulty, P2P multicast group/port, consensus quorum fraction, and file paths for persistent state.
+ Enables rapid customization for different election scenarios, network topologies, and performance requirements without touching core logic.

## Usage with CLI
All commands are wrapped in cli.py. If your server runs on a different host/port, use --server `<URL>`.
### 1. Generate key pair 
```
python3 cli.py genkey
```
This creates:
+ `private_key.pem` (encrypted with an optinal passphrase) in the data folder
+ `public_key.pem` (used as your voter ID) in the data folder
### 2. Register your node
```
python3 cli.py register --ip <YOUR_IP> --port <PORT>
```
Calls `POST /register_node` to broadcast your public key and address.
### 3. Cast your vote
```
python3 cli.py vote --candidate <CANDIDATE>
```
Signs and submits your vote via `POST /vote`.
### 4. Mine pending votes
```
python3 cli.py mine
```
Invokes `POST /mine`, performing PoW, prepare/commit consensus, and commits on success
### 5. Check your vote & results
```
python3 cli.py myvote
curl http://<YOUR_IP>:<PORT>/chain
curl http://<YOUR_IP>:<PORT>/results
```


