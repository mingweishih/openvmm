// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! A simple [`tracing_subscriber::Layer`] that sends trace events to the mesh
//! tracing backend via [`TraceWriter`].
//!
//! This is a simplified version of the JSON layer from `underhill_core` that
//! formats the event message and fields into a plain text message suitable for
//! the GET tracing protocol.

use mesh_tracing::Level;
use mesh_tracing::TraceWriter;
use mesh_tracing::Type;
use std::fmt::Write;
use std::time::SystemTime;
use tracing::Subscriber;
use tracing::field::Field;
use tracing::field::Visit;
use tracing_subscriber::Layer;
use tracing_subscriber::registry::LookupSpan;

/// A tracing layer that forwards events through a [`TraceWriter`].
pub(crate) struct SimpleMeshLayer {
    writer: TraceWriter,
}

impl SimpleMeshLayer {
    pub(crate) fn new(writer: TraceWriter) -> Self {
        Self { writer }
    }
}

fn to_mesh_level(level: &tracing::Level) -> Level {
    match *level {
        tracing::Level::TRACE => Level::Trace,
        tracing::Level::DEBUG => Level::Debug,
        tracing::Level::INFO => Level::Info,
        tracing::Level::WARN => Level::Warn,
        tracing::Level::ERROR => Level::Error,
    }
}

struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{:?}", value);
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            let _ = write!(self.fields, "{}={:?}", field.name(), value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            if !self.fields.is_empty() {
                self.fields.push(' ');
            }
            let _ = write!(self.fields, "{}={}", field.name(), value);
        }
    }
}

impl<S> Layer<S> for SimpleMeshLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor {
            message: String::new(),
            fields: String::new(),
        };
        event.record(&mut visitor);

        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        let target = event.metadata().target().as_bytes().to_vec();
        let fields_bytes = if visitor.fields.is_empty() {
            None
        } else {
            Some(visitor.fields.into_bytes())
        };

        self.writer.send(
            Type::Event,
            timestamp,
            to_mesh_level(event.metadata().level()),
            None, // name
            Some(target),
            fields_bytes,
            None, // activity_id
            None, // related_activity_id
            None, // correlation_id
            visitor.message.into_bytes(),
        );
    }
}
