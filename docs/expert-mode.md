# Expert Mode (Developer Mode)

Dash Evo Tool ships with a clean, simplified UI by default. Expert mode (also
referred to as developer mode internally) is an optional toggle that unlocks
advanced and developer-oriented controls for users who need them.

**Default: off.** A fresh install is in the safer, simpler everyday-user
experience. Leave it off unless you are developing, testing, or knowingly need
the additional controls described below.

## Where to find the toggle

Expert mode lives in the UI:

1. Open **Network Settings** (the network chooser screen).
2. Expand **Advanced Settings**.
3. Under **Configuration Options**, toggle **Expert mode**.

The toggle text reads "Expert mode" with the helper line "Enable advanced
features". When checked, the application immediately reveals the advanced
controls described below and persists the change so it remains active across
restarts.

## What Expert mode changes

Enabling Expert mode:

- **Reveals the Devnet and Local (regtest) network entries** in the network
  chooser.
- **Exposes Dash Core RPC backend selection and credentials.** SPV (light
  client) is the default for everyday users; Expert mode reveals the advanced
  option to switch a network to a local Dash Core RPC backend and configure its
  RPC/ZMQ connection details.
- **Exposes additional developer tools** (e.g. SPV peer source overrides, sync
  reset/diagnostic actions, and other power-user utilities under "Developer
  Tools" in Network Settings).
- **Permits advanced state transition signing.** The application allows
  signing with any key security level and any key purpose (i.e. less strict
  signing-options validation) when Expert mode is enabled. With it disabled,
  signing follows the safer default rules enforced by the platform.
- **Exposes experimental or advanced wallet, token, and shielded options** in
  various screens (e.g. additional fields, raw inputs, less guard-railed
  flows).
- **Disables UI animations.** Animations are intentionally turned off in
  Expert mode for a denser, snappier developer-oriented experience.

Disabling Expert mode returns the UI to the everyday-user experience,
re-enables animations, and hides the advanced controls. It does not delete
saved settings; if you previously configured a local Core backend or other
advanced options, those settings remain in the app data/configuration.

## `.env` variable

The toggle is persisted to the global `.env` file in the application
directory as a single boolean:

```
DEVELOPER_MODE=false
```

- The default is `false` (or absent — both are treated as off).
- Set `DEVELOPER_MODE=true` to enable Expert mode at startup without using the
  UI toggle.
- The variable is global — it applies to all networks (Mainnet, Testnet,
  Devnet, Local).

The application directory is:

| Operating System | Path |
| - | - |
| macOS | `~/Library/Application Support/Dash-Evo-Tool/.env` |
| Windows | `C:\Users\<User>\AppData\Roaming\Dash-Evo-Tool\config\.env` |
| Linux | `~/.config/dash-evo-tool/.env` |

## Migration note: obsolete per-network values

Earlier builds used per-network entries such as `MAINNET_developer_mode=true`
and `TESTNET_developer_mode=false` in `.env`. **These are obsolete.** Expert
mode is now a single global setting (`DEVELOPER_MODE`). Any leftover
`*_developer_mode` entries from older configurations are ignored and can be
removed; the safe default is off and is captured by the global
`DEVELOPER_MODE=false` line in `.env.example`.

## Should I turn it on?

Generally, no — leave Expert mode off unless one of the following applies:

- You are developing or testing Dash Evo Tool itself.
- You explicitly need the Dash Core RPC backend, Devnet/Local networks, or
  the developer tools panel.
- You are debugging an issue and need access to advanced signing or raw
  controls.

For everyday wallet, identity, DPNS, token, and DashPay use, the default
(Expert mode off) is the recommended configuration.
