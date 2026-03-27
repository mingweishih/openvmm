// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Root binary crate for the migration agent — a minimal standalone OpenHCL
//! application with host-directed logging and `ohcldiag-dev` diagnostics
//! support.
//!
//! This is a multi-binary: the kernel boots `/underhill-init` which is a
//! symlink to this binary. We dispatch based on `argv0` to run
//! `underhill_init` (PID 1 setup) or `migration_agent_core` (the agent).

#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
fn main() {
    unimplemented!("migration_agent only runs on Linux");
}

/// Entry point — dispatches based on argv0.
///
/// - `underhill-init` → [`underhill_init::main`] (mounts filesystems, loads
///   kernel modules, then execs `/bin/openvmm_hcl` which re-enters this
///   binary with the default argv0).
/// - anything else → [`migration_agent_core::main`].
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    let argv0 = std::path::PathBuf::from(std::env::args_os().next().unwrap());
    match argv0.file_name().unwrap().to_str().unwrap() {
        "underhill-init" => underhill_init::main(),
        _ => migration_agent_core::main(),
    }
}
