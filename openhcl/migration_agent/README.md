# Migration Agent

A minimal standalone OpenHCL application that replaces the full `openvmm_hcl`
VMM while retaining host-directed logging and diagnostics (`ohcldiag-dev`)
support. Includes CVM (Confidential VM) awareness out of the box.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Host (Windows / Hyper-V)                               │
│                                                         │
│   ohcldiag-dev ◄──── AF_VSOCK ────► DiagServer          │
│   (inspect, kmsg)                   (ports 1 & 2)       │
│                                                         │
│   Host tracing ◄──── VMBus GET ───► TracingBackend      │
│   collector           channel       (get_tracing)       │
└─────────────────────────────────────────────────────────┘
                           │
┌──────────────────────────┼──────────────────────────────┐
│  VTL2 (OpenHCL Linux)    │                              │
│                          ▼                              │
│  underhill-init (PID 1)                                 │
│    ├─ mounts /proc, /sys, /dev                          │
│    ├─ loads kernel modules                              │
│    └─ exec /bin/openvmm_hcl  ◄── migration_agent bin    │
│                                                         │
│  migration_agent_core                                   │
│    ├─ TracingBackend  → VMBus GET channel → host        │
│    │   └─ CVM filter (blocks non-CVM_ALLOWED events)   │
│    ├─ kmsg layer      → /dev/kmsg → serial (COM3)      │
│    └─ DiagServer      → AF_VSOCK → ohcldiag-dev        │
│        └─ CVM mode: only inspect (with sensitivity)    │
└─────────────────────────────────────────────────────────┘
```

### Tracing pipeline

1. **`TracingBackend`** opens the VMBus GET (Guest Emulation Transport) log
   channel and spawns a task that serializes trace events in the GET protocol
   format and writes them to the host.

2. **`init_tracing`** registers two `tracing_subscriber` layers:
   - A **mesh layer** that pushes events through a bounded channel to the
     backend task.
   - A **kmsg layer** that writes human-readable output to `/dev/kmsg`
     (visible on COM3 / serial).

3. The log level defaults to `info` and can be changed at runtime via the
   `OPENVMM_LOG` environment variable or through `ohcldiag-dev inspect`.

### Diagnostics server

A ttrpc server on `AF_VSOCK` ports 1 (control) and 2 (data) — the same
ports used by `underhill_core`. This means `ohcldiag-dev` connects to the
migration agent exactly the same way it connects to a regular OpenHCL VM:

```bash
ohcldiag-dev inspect <vm-name>
ohcldiag-dev kmsg <vm-name>
```

### CVM (Confidential VM) support

The migration agent is CVM-aware. When the IGVM manifest sets
`OPENHCL_CONFIDENTIAL=1` (automatically done by the CVM manifests), the
following restrictions activate at runtime — no code changes needed:

| Capability | Non-CVM | CVM |
|---|---|---|
| **Tracing** | All events emitted | Only events tagged `CVM_ALLOWED` are emitted |
| **Diag server** | Full (`inspect`, `exec`, `kmsg`, file ops) | `inspect` only (with sensitivity filtering) |
| **Crash dumps** | Enabled (via `underhill-crash`) | Disabled (`core_pattern` set to empty) |
| **Host entropy** | Credited to kernel entropy pool | Written without crediting (untrusted host) |

CVM status is determined by the `underhill_confidentiality` crate:

- **`is_confidential_vm()`** — `true` when `OPENHCL_CONFIDENTIAL=1`
- **`confidential_filtering_enabled()`** — `true` when confidential *and*
  `OPENHCL_CONFIDENTIAL_DEBUG` is *not* set. This is the single source of
  truth for all filtering decisions.

#### Tagging trace events

When adding new trace events, tag them with `CVM_ALLOWED` if they are safe
to emit from a CVM (no guest secrets, no sensitive state):

```rust
use cvm_tracing::CVM_ALLOWED;

// Safe — no guest secrets:
tracing::info!(CVM_ALLOWED, "migration_agent starting");

// Contains sensitive guest state — do NOT tag:
tracing::debug!(register_state = ?regs, "VP registers");
```

Untagged events pass through in non-CVM mode but are blocked when
`confidential_filtering_enabled()` returns `true`.

#### Attestation (future work)

Full CVM migration requires re-establishing attestation on the destination.
The attestation stack (`underhill_attestation`, `tee_call`,
`openhcl_attestation_protocol`) handles:

- Hardware attestation reports (SNP / TDX / VBS) via `tee_call`
- Secure Key Release (SKR) via the GET IGVM_ATTEST host requests
- VMGS encryption key management

This is **not yet integrated** into the migration agent. For prototype use,
build with the CVM dev manifest (`x64-cvm`) which sets
`OPENHCL_CONFIDENTIAL_DEBUG=1` — this enables CVM hardware isolation while
relaxing the diagnostic restrictions for development.

## Crate layout

| Crate                    | Type    | Description |
|--------------------------|---------|-------------|
| `migration_agent`        | binary  | Thin entry point; calls `migration_agent_core::main()` |
| `migration_agent_core`   | library | Tracing setup, diag server, main event loop |

## Building

### Native check (host architecture)

```bash
cargo check -p migration_agent
cargo clippy --all-targets -p migration_agent -p migration_agent_core
```

### Cross-compile for OpenHCL (musl, static)

```bash
cargo build --target x86_64-unknown-linux-musl -p migration_agent
# or for aarch64:
cargo build --target aarch64-unknown-linux-musl -p migration_agent
```

### Package as IGVM

```bash
# 1. Build the statically-linked binary
cargo build --target x86_64-unknown-linux-musl -p migration_agent --release

# 2. Generate the initrd using the migration-agent-specific rootfs config
OPENHCL_OPENVMM_PATH=target/x86_64-unknown-linux-musl/release/migration_agent \
OPENHCL_MODULES_PATH=<kernel-modules-path> \
  python3 openhcl/gen_init_ramfs.py \
    openhcl/migration_agent_rootfs.config \
    -o migration_agent_initrd.cpio.gz

# 3. Produce the IGVM file (requires boot shim + kernel + igvmfilegen)
igvmfilegen manifest \
    -m <manifest.json> \
    -r <resources.json> \
    -o migration_agent.bin
```

Alternatively, reuse the flowey pipeline with a custom binary:

```bash
# Non-CVM
cargo xflowey build-igvm x64 \
    --custom-openvmm-hcl target/x86_64-unknown-linux-musl/release/migration_agent

# CVM (uses CVM kernel + CVM manifest with SNP/TDX/VBS guest configs)
cargo xflowey build-igvm x64-cvm \
    --custom-openvmm-hcl target/x86_64-unknown-linux-musl/release/migration_agent
```

The CVM build differs from non-CVM in:

| | `x64` | `x64-cvm` |
|---|---|---|
| Isolation type | `none` | SNP / TDX / VBS guest configs |
| Kernel | Standard | CVM-specific (SEV-SNP / TDX enabled) |
| VTL2 memory | 131072 pages | 163840 pages |
| Sidecar | Yes | No |
| Env vars | — | `OPENHCL_CONFIDENTIAL=1` (release) |

## Extending

To add your own logic, edit `migration_agent_core/src/lib.rs`:

- Add state to the `AgentState` struct (it is exposed via `ohcldiag-dev inspect`).
- Add async work to the `do_main` event loop.
- Use `tracing::info!(CVM_ALLOWED, ...)` for events safe to emit from CVMs.
- Use plain `tracing::info!(...)` for events containing sensitive data — they
  will be automatically filtered in CVM mode.
