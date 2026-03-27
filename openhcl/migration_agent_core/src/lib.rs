// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Migration agent core — a minimal standalone OpenHCL application that
//! provides logging/tracing back to the host via the GET (Guest Emulation
//! Transport) VMBus channel and exposes a uhdiag diagnostics server for
//! `ohcldiag-dev` connectivity.
//!
//! # Architecture
//!
//! The tracing pipeline mirrors the one used by `underhill_core`:
//!
//! 1. **TracingBackend** opens the VMBus GET tracing channel and
//!    creates a [`mesh_tracing::TracingBackend`]. This backend runs a task
//!    that receives `TracingRequest`s from all processes/tasks and writes
//!    them to the host over VMBus.
//!
//! 2. **init_tracing** registers two `tracing_subscriber` layers:
//!    - A **JSON mesh layer** that serializes events and sends them through
//!      the mesh channel to the backend task.
//!    - A **kmsg layer** that writes human-readable events to `/dev/kmsg`
//!      (visible on serial / COM3).
//!
//! 3. **DiagServer** listens on `AF_VSOCK` ports 1 (control) and 2 (data).
//!    `ohcldiag-dev` connects here for `inspect`, `kmsg`, and other
//!    operations.

#![cfg(target_os = "linux")]
#![forbid(unsafe_code)]

mod mesh_layer;
mod tracing_setup;

use anyhow::Context;
use cvm_tracing::CVM_ALLOWED;
use diag_server::DiagServer;
use futures::FutureExt;
use futures::StreamExt;
use futures_concurrency::stream::Merge;
use inspect::Inspect;
use inspect::SensitivityLevel;
use mesh_tracing::TracingBackend;
use pal_async::DefaultDriver;
use pal_async::DefaultPool;
use std::pin::pin;
use std::time::Duration;
use tracing_setup::init_tracing;
use tracing_setup::init_tracing_backend;
use vmsocket::VmAddress;

/// Entry point for the migration agent.
pub fn main() -> anyhow::Result<()> {
    // Set up the tracing backend (opens VMBus GET log channel).
    let (_, tracing_driver) = DefaultPool::spawn_on_thread("tracing");
    let mut tracing = init_tracing_backend(tracing_driver.clone())?;
    init_tracing(tracing_driver, tracing.tracer()).context("failed to init tracing")?;

    DefaultPool::run_with(|driver| do_main(driver, tracing))
}

/// State visible via `ohcldiag-dev inspect`.
#[derive(Inspect)]
struct AgentState {
    #[inspect(safe)]
    status: &'static str,
}

async fn do_main(driver: DefaultDriver, tracing: TracingBackend) -> anyhow::Result<()> {
    tracing::info!(CVM_ALLOWED, "migration_agent starting");

    // ── Diagnostics server (uhdiag) ──────────────────────────────────────
    let diag_server = DiagServer::new_vsock(
        VmAddress::vsock_any(diag_proto::VSOCK_CONTROL_PORT),
        VmAddress::vsock_any(diag_proto::VSOCK_DATA_PORT),
    )
    .context("failed to create diagnostics server")?;

    let (request_send, mut request_recv) = mesh::channel();
    let (_cancel_send, cancel) = mesh::oneshot();

    let mut serve = pin!(diag_server.serve(&driver, cancel, request_send).fuse());

    let state = AgentState { status: "running" };

    // ── Signal VTL0 start to the host ────────────────────────────────────
    // Hyper-V waits for this signal before transitioning the VM to the
    // "running" state.  Without it the VM stays stuck in a starting state.
    signal_vtl0_started(&driver)
        .await
        .context("failed to signal vtl0 started")?;

    tracing::info!(
        CVM_ALLOWED,
        "migration_agent ready — diagnostics server listening"
    );

    // ── Main event loop ──────────────────────────────────────────────────
    // Handle diag requests (inspect, etc.) while the server runs.
    enum Event {
        Diag(diag_server::DiagRequest),
        ServerDone(anyhow::Result<()>),
    }

    loop {
        let event = {
            let mut stream = ((&mut request_recv).map(Event::Diag),).merge();

            futures::select! { // merge semantics
                ev = stream.next().fuse() => match ev {
                    Some(ev) => ev,
                    None => break,
                },
                r = serve => {
                    Event::ServerDone(r)
                }
            }
        };

        match event {
            Event::Diag(request) => {
                match request {
                    diag_server::DiagRequest::Inspect(deferred) => deferred.respond(|resp| {
                        resp.sensitivity_field("state", SensitivityLevel::Safe, &state)
                            .sensitivity_field(
                                "build_info",
                                SensitivityLevel::Safe,
                                build_info::get(),
                            );
                    }),
                    // For now, we only support inspect. Other diag requests are
                    // acknowledged but not acted upon.
                    diag_server::DiagRequest::Crash(_pid) => {
                        tracing::warn!("crash request received — ignoring");
                    }
                    diag_server::DiagRequest::Start(rpc) => {
                        rpc.handle_failable_sync(|_| {
                            anyhow::bail!("start not supported by migration_agent")
                        });
                    }
                    diag_server::DiagRequest::Restart(rpc) => {
                        rpc.handle_sync(|_| {
                            Err(mesh::error::RemoteError::new(anyhow::anyhow!(
                                "restart not supported"
                            )))
                        });
                    }
                    diag_server::DiagRequest::Pause(rpc) => {
                        rpc.handle_sync(|_| {
                            Err(mesh::error::RemoteError::new(anyhow::anyhow!(
                                "pause not supported"
                            )))
                        });
                    }
                    diag_server::DiagRequest::Resume(rpc) => {
                        rpc.handle_sync(|_| {
                            Err(mesh::error::RemoteError::new(anyhow::anyhow!(
                                "resume not supported"
                            )))
                        });
                    }
                    diag_server::DiagRequest::Save(rpc) => {
                        rpc.handle_sync(|_| {
                            Err(mesh::error::RemoteError::new(anyhow::anyhow!(
                                "save not supported"
                            )))
                        });
                    }
                    diag_server::DiagRequest::PacketCapture(rpc) => {
                        rpc.handle_sync(|_| {
                            Err(mesh::error::RemoteError::new(anyhow::anyhow!(
                                "packet capture not supported"
                            )))
                        });
                    } // Conditionally compiled diag requests from underhill_core
                      // are not present here since we don't enable those features.
                }
            }
            Event::ServerDone(r) => {
                r.context("diagnostics server failed")?;
                break;
            }
        }
    }

    // Graceful shutdown
    tracing::info!(CVM_ALLOWED, "migration_agent shutting down");
    mesh::CancelContext::new()
        .with_timeout(Duration::from_secs(5))
        .until_cancelled(tracing.shutdown())
        .await
        .ok();

    Ok(())
}

/// Tell Hyper-V that VTL0 has started successfully.
///
/// This opens a temporary GET (Guest Emulation Transport) VMBus connection,
/// sends the `CompleteStartVtl0` message, and then tears the connection down
/// so the GET channel is free for other uses.
async fn signal_vtl0_started(driver: &DefaultDriver) -> anyhow::Result<()> {
    tracing::info!(CVM_ALLOWED, "signaling vtl0 started");
    let (client, task) = guest_emulation_transport::spawn_get_worker(driver.clone())
        .await
        .context("failed to spawn GET worker")?;
    client.complete_start_vtl0(None).await;
    // Drop the client so the GET channel is released for reuse.
    drop(client);
    task.await.context("GET worker failed")?;
    tracing::info!(CVM_ALLOWED, "signaled vtl0 started");
    Ok(())
}
