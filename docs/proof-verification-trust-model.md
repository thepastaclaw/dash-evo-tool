# Proof verification trust model

Dash Evo Tool (DET) verifies Dash Platform DAPI responses by default. The SDK
requests proofs for normal `Fetch` and `FetchMany` calls, verifies the
Drive/GroveDB proof, and verifies the quorum signature using quorum data supplied
by DET's SDK context provider.

## Current providers

DET has two context providers for SDK proof verification:

- **SPV provider** (`src/context_provider_spv.rs`) is the default for fresh
  installs. It serves cached data contracts/token configurations from DET's
  database and resolves quorum public keys from the built-in SPV client. This
  does **not** require a local Dash Core RPC node, but SPV must be synced far
  enough to know the quorum/masternode data needed by the proof.
- **RPC provider** (`src/context_provider.rs`) is the expert opt-in backend for
  users who run a local Dash Core node. It serves the same cached data
  contracts/token configurations and resolves quorum public keys through Dash
  Core RPC.

`AppContext::new` initializes the SDK with the SPV provider first and only
rebinds to the RPC provider when the saved `CoreBackendMode` is `Rpc`. This
means the safe answer to "use DET without Dash Core" is **SPV mode**, not
skipped proof verification.

## Why DET should not silently bypass proofs

A global "assume all proofs are valid" fallback would change DET from validating
Platform state to trusting whichever DAPI endpoint answered the request. That is
acceptable only if it is explicit, heavily labeled, and restricted to operations
whose result cannot spend funds or mutate Platform state.

Do **not** implement proof bypass by swallowing `ContextProviderError` or
returning dummy quorum keys. The SDK's context provider is part of proof
verification; faking it would either still fail later or make the trust boundary
unclear. It would also make real proof-verification bugs look like successful
queries.

The current SDK also does not expose a broad safe unproved path for the query
types DET uses most often. `SdkBuilder::with_proofs(false)` toggles request
construction, but normal `Fetch`/`FetchMany` paths still parse via `FromProof`;
DET document queries currently force `prove: true`; and `FetchUnproved` support
is limited to specific SDK types. A scoped unverified mode would therefore need
explicit SDK support for each query family rather than a one-line DET setting.

## Operation classes

### Platform read-only queries

Examples: documents, identities, contracts, tokens, and DPNS.

- Local Dash Core RPC: not needed in SPV mode.
- SPV/proof context: needed for normal verified SDK fetches.
- Bypass policy: only a future explicitly labeled unverified API may bypass, and
  only if the SDK supports decoding unproved responses for that exact query type.

### Platform state transitions

Examples: identity, document, token, wallet/platform credit actions.

- Local Dash Core RPC: usually not needed in SPV mode, except flows that
  explicitly opt into RPC-only Core wallet behavior.
- SPV/proof context: needed.
- Bypass policy: never bypass. These spend credits, sign state transitions, or
  depend on verified nonces/balances.

### Core-chain wallet balance/history/send in SPV mode

- Local Dash Core RPC: not needed; DET uses SPV wallet state and P2P broadcast
  where supported.
- SPV/proof context: SPV sync is required.
- Bypass policy: never bypass. These depend on chain validation and wallet state.

### RPC-only tools

Examples: masternode-list diff inspector, Core wallet listing, mining, and
local-node tools.

- Local Dash Core RPC: required.
- SPV/proof context: no substitute in pure SPV mode.
- Bypass policy: disable the tool or show a clear "requires local Dash Core
  node" message.

### Offline/local-only tools

Examples: deserializers, static tool descriptions, and local settings/wallet
metadata that does not refresh network state.

- Local Dash Core RPC: not needed.
- SPV/proof context: not needed.
- Bypass policy: safe without proof bypass because no network response is being
  trusted.

## If an unverified read-only mode is added later

A future implementation should be scoped and auditable:

1. Add an explicit setting named something like **Trusted DAPI read-only mode**
   or **Unverified read-only queries**. Do not call it simply "proof bypass" in
   the UI.
2. Gate it behind Expert/Developer mode and show a persistent warning: responses
   are not cryptographically verified and may be malicious, stale, or
   inconsistent.
3. Use explicit unproved SDK APIs per query type. Do not disable proof
   verification globally and do not catch all proof errors.
4. Allow only read-only queries. Block state transitions, wallet sends, top-ups,
   withdrawals, token actions, and any flow that uses returned data for
   signing/spending decisions.
5. Mark every result/banner/log entry as **Unverified** so copied data and
   screenshots preserve the trust status.
6. Add tests for both modes: verified mode still requests and verifies proofs;
   unverified mode is only reachable for allowlisted read-only tasks and is
   rejected for state-changing tasks.

Until those SDK and UI pieces exist, DET's supported no-Core mode is the
built-in SPV backend with proof verification intact.
