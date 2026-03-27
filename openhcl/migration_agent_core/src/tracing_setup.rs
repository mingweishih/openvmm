// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tracing setup for migration_agent.
//!
//! This is a simplified version of the tracing pipeline from
//! `underhill_core::get_tracing`. It opens the VMBus GET tracing channel,
//! feeds trace events to the host in the GET protocol format, and
//! simultaneously writes human-readable events to `/dev/kmsg`.

use crate::mesh_layer::SimpleMeshLayer;
use anyhow::Context;
use cvm_tracing::CVM_ALLOWED;
use futures::FutureExt;
use futures::StreamExt;
use futures_concurrency::stream::Merge;
use get_helpers::build_tracelogging_notification_buffer;
use get_protocol::GET_LOG_INTERFACE_GUID;
use get_protocol::LogFlags;
use get_protocol::LogLevel;
use get_protocol::LogType;
use mesh::rpc::Rpc;
use mesh_tracing::Level;
use mesh_tracing::RemoteTracer;
use mesh_tracing::TracingBackend;
use mesh_tracing::TracingRequestStream;
use mesh_tracing::Type;
use pal_async::driver::SpawnDriver;
use pal_async::task::Spawn;
use tracing_helpers::formatter::FieldFormatter;
use tracing_subscriber::Layer;
use tracing_subscriber::fmt::format::Format;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use vmbus_async::async_dgram::AsyncSendExt;

fn tracing_log_level(level: Level) -> LogLevel {
    match level {
        Level::Trace | Level::Debug => LogLevel::VERBOSE,
        Level::Info => LogLevel::INFORMATION,
        Level::Warn => LogLevel::WARNING,
        Level::Error => LogLevel::ERROR,
    }
}

/// Reads an environment variable, falling back to a legacy variable (replacing
/// "OPENVMM_" with "HVLITE_") if the original is not set.
fn legacy_openvmm_env(name: &str) -> Result<String, std::env::VarError> {
    std::env::var(name).or_else(|_| {
        std::env::var(format!(
            "HVLITE_{}",
            name.strip_prefix("OPENVMM_").unwrap_or(name)
        ))
    })
}

/// Initializes the tracing backend, opening the VMBus pipe to send tracing
/// events to the host.
pub fn init_tracing_backend(driver: impl 'static + SpawnDriver) -> anyhow::Result<TracingBackend> {
    let trace_filter = legacy_openvmm_env("OPENVMM_LOG").unwrap_or_else(|_| "info".to_owned());
    let perf_trace_filter =
        legacy_openvmm_env("OPENVMM_PERF_TRACE").unwrap_or_else(|_| "off".to_owned());

    let pipe = vmbus_user_channel::open_uio_device(&GET_LOG_INTERFACE_GUID)
        .and_then(|dev| vmbus_user_channel::message_pipe(&driver, dev))
        .map_err(|err| {
            tracing::error!(
                CVM_ALLOWED,
                error = &err as &dyn std::error::Error,
                "failed to open the vmbus tracing channel"
            );
        })
        .ok();

    let mut get_backend = pipe.map(|pipe| GetTracingBackend { pipe });

    TracingBackend::new(
        driver,
        trace_filter,
        perf_trace_filter,
        async move |requests, flush| {
            if let Some(get_backend) = &mut get_backend {
                get_backend.run(requests, flush).await;
            }
        },
    )
}

struct GetTracingBackend {
    pipe: vmbus_async::pipe::MessagePipe<vmbus_user_channel::MappedRingMem>,
}

impl GetTracingBackend {
    async fn run(
        &mut self,
        requests: TracingRequestStream,
        mut flush: mesh::Receiver<Rpc<(), ()>>,
    ) {
        let mut tracing_requests = requests.map(|request| {
            let log_type = match request.log_type {
                Type::Event => LogType::EVENT,
                Type::SpanEnter => LogType::SPAN_ENTER,
                Type::SpanExit => LogType::SPAN_EXIT,
            };

            build_tracelogging_notification_buffer(
                log_type,
                tracing_log_level(request.level),
                LogFlags::new(),
                request.activity_id,
                request.related_activity_id,
                request.correlation_id,
                request.name.as_ref().map(Vec::as_ref),
                request.target.as_ref().map(Vec::as_ref),
                request.fields.as_ref().map(Vec::as_ref),
                request.message.as_ref(),
                request.timestamp,
            )
        });

        enum Event {
            Trace(Vec<u8>),
            Flush(Rpc<(), ()>),
            Done,
        }

        let (_, mut write) = self.pipe.split();
        loop {
            let mut streams = (
                (&mut tracing_requests).map(Event::Trace),
                (&mut flush)
                    .map(Event::Flush)
                    .chain(futures::stream::repeat_with(|| Event::Done)),
            )
                .merge();

            let flush_rpc = loop {
                let trace_type = streams.next().await.unwrap();
                match trace_type {
                    Event::Trace(data) => {
                        write.send(&data).await.ok();
                    }
                    Event::Flush(rpc) => break Some(rpc),
                    Event::Done => break None,
                }
            };

            // Drain everything we've got.
            while let Some(data) = tracing_requests.next().now_or_never().flatten() {
                write.send(&data).await.ok();
            }

            // Wait for the host to read everything.
            write.wait_empty().await.ok();

            if let Some(rpc) = flush_rpc {
                rpc.complete(());
            } else {
                break;
            }
        }
    }
}

/// Enables tracing output to the tracing task and to stderr/kmsg.
pub fn init_tracing(spawn: impl Spawn, tracer: RemoteTracer) -> anyhow::Result<()> {
    if legacy_openvmm_env("OPENVMM_DISABLE_TRACING_RATELIMITS").is_ok_and(|v| !v.is_empty()) {
        tracelimit::disable_rate_limiting(true);
    }

    // Format events and send them to the mesh tracing backend.
    let mesh_layer = SimpleMeshLayer::new(tracer.trace_writer);

    // Output nicely readable events to kmsg (and therefore also serial).
    let kmsg_layer = tracing_subscriber::fmt::layer()
        .event_format(
            Format::default()
                .without_time()
                .with_ansi(false)
                .with_target(false),
        )
        .fmt_fields(FieldFormatter)
        .log_internal_errors(true)
        .with_writer(kmsg_writer::KmsgWriter::new(
            kmsg_defs::UNDERHILL_KMSG_FACILITY,
        )?);

    // Filter out events that aren't allowed for CVMs, when filtering is enabled.
    let cvm_filter = underhill_confidentiality::confidential_filtering_enabled()
        .then(cvm_tracing::confidential_event_filter);

    let output_layers = mesh_layer.and_then(kmsg_layer);
    let with_cvm_filter = output_layers.with_filter(cvm_filter);

    // Filter events based on the updatable-via-inspect target filter.
    let (combined, update_fut) = tracer.trace_filter.apply(with_cvm_filter, |filter| {
        let targets = filter.parse::<tracing_subscriber::filter::Targets>()?;
        Ok(targets)
    })?;

    tracing_subscriber::registry()
        .with(combined)
        .try_init()
        .context("failed to enable tracing")?;

    spawn.spawn("tracing_filter_updater", update_fut).detach();

    Ok(())
}
