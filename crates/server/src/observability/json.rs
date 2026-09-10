//! Rendering log records as one JSON object per line.
//!
//! `log_format = "json"` exists for a collector — Loki, Datadog, a `journald`
//! shipper — and a collector parses lines, so the format has to be JSON all
//! the way down or the whole stream is dropped as unparseable.
//!
//! # Why not `tracing_subscriber`'s own JSON formatter
//!
//! [`tracing_subscriber::fmt::format::Json`] renders *event* fields with
//! `tracing-serde`, straight from the value into the serializer. It never
//! calls the layer's [`FormatFields`] — that is used for span fields only. So
//! `fmt::layer().json().fmt_fields(RedactingFields)` compiles, looks right,
//! and writes every access token in the clear: the redaction is bypassed on
//! precisely the records that carry credentials. RFC 9700 §4.2/§4.3 is not
//! satisfied by a formatter that redacts one of the two formats.
//!
//! Hence a formatter of our own. It walks the fields with a visitor that runs
//! every value through [`redact_field`], the same function the text layer
//! uses, so the two renderers cannot drift and the corpus in
//! `tests/log_redaction.rs` is meaningful against both.
//!
//! # Shape of a line
//!
//! ```json
//! {"timestamp":"2026-09-10T19:54:09.414962Z","level":"INFO",
//!  "target":"asterius_web","fields":{"message":"token issued","tenant":"demo"},
//!  "span":{"name":"token","request_id":"01J..."},
//!  "spans":[{"name":"token","request_id":"01J..."}]}
//! ```
//!
//! `level` and the span fields are there on purpose: the level is what an
//! alert rule matches on, and the span carries the correlation id that ties a
//! request's lines together once they are interleaved with a thousand others.

use super::redact::redact_field;
use serde_json::{Map, Value};
use std::fmt;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::field::{RecordFields, VisitOutput};
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::registry::LookupSpan;

/// A [`FormatFields`] that renders a record's fields as a JSON object,
/// redacting every value on the way out.
///
/// Used for span fields, whose formatted form is cached by the `fmt` layer and
/// read back by [`RedactingJson`]; the string it produces is therefore always
/// a parseable JSON object, empty braces included.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactingJsonFields;

impl<'writer> FormatFields<'writer> for RedactingJsonFields {
    fn format_fields<R: RecordFields>(
        &self,
        mut writer: Writer<'writer>,
        fields: R,
    ) -> fmt::Result {
        let mut visitor = RedactingJsonVisitor::default();
        fields.record(&mut visitor);
        let values = visitor.finish()?;
        write!(writer, "{}", Value::Object(values))
    }

    fn add_fields(
        &self,
        current: &'writer mut FormattedFields<Self>,
        fields: &tracing::span::Record<'_>,
    ) -> fmt::Result {
        // Appending to a serialized object would produce `{"a":1}{"b":2}`, so
        // the fields recorded earlier are read back and re-serialized with the
        // new ones. Costly, and the price of storing formatted fields as a
        // string; `tracing_subscriber`'s own JSON fields do the same.
        let mut visitor = RedactingJsonVisitor::default();
        if !current.fields.is_empty() {
            let previous: Map<String, Value> =
                serde_json::from_str(&current.fields).map_err(|_| fmt::Error)?;
            visitor.values = previous;
        }
        fields.record(&mut visitor);
        let values = visitor.finish()?;
        current.fields = Value::Object(values).to_string();
        Ok(())
    }
}

/// A [`FormatEvent`] writing one JSON object per line.
#[derive(Debug, Clone, Copy, Default)]
pub struct RedactingJson;

impl<S, N> FormatEvent<S, N> for RedactingJson
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();

        let mut timestamp = String::new();
        SystemTime.format_time(&mut Writer::new(&mut timestamp))?;

        let mut visitor = RedactingJsonVisitor::default();
        event.record(&mut visitor);
        let fields = visitor.finish()?;

        let mut line = Map::new();
        line.insert("timestamp".to_owned(), Value::String(timestamp));
        line.insert(
            "level".to_owned(),
            Value::String(metadata.level().as_str().to_owned()),
        );
        line.insert(
            "target".to_owned(),
            Value::String(metadata.target().to_owned()),
        );
        line.insert("fields".to_owned(), Value::Object(fields));

        // The correlation half: a request's lines are only followable if the
        // span that carries its id travels with them.
        let mut spans = Vec::new();
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let mut entry = Map::new();
                if let Some(formatted) = span.extensions().get::<FormattedFields<N>>()
                    && let Ok(Value::Object(recorded)) =
                        serde_json::from_str::<Value>(&formatted.fields)
                {
                    entry.extend(recorded);
                }
                entry.insert("name".to_owned(), Value::String(span.name().to_owned()));
                spans.push(Value::Object(entry));
            }
        }
        if let Some(current) = spans.last().cloned() {
            line.insert("span".to_owned(), current);
        }
        if !spans.is_empty() {
            line.insert("spans".to_owned(), Value::Array(spans));
        }

        writeln!(writer, "{}", Value::Object(line))
    }
}

/// Collects fields into a JSON object, redacting each value as it arrives.
#[derive(Default)]
struct RedactingJsonVisitor {
    values: Map<String, Value>,
}

impl RedactingJsonVisitor {
    fn insert(&mut self, name: &str, value: Value) {
        self.values.insert(name.to_owned(), value);
    }

    /// Records a value rendered as text: the redacted form is what is stored,
    /// always as a JSON string.
    fn record_text(&mut self, name: &str, value: &str) {
        self.insert(name, Value::String(redact_field(name, value)));
    }

    /// Records a value that has a JSON type of its own.
    ///
    /// A number stays a number unless redaction changed it — a collector that
    /// can range-query `status` or `deleted` is most of the reason to emit
    /// JSON at all — but a field *named* like a secret is redacted whatever
    /// its shape, and then the redacted string wins over the type.
    fn record_scalar(&mut self, name: &str, rendered: &str, native: Value) {
        let redacted = redact_field(name, rendered);
        if redacted == rendered {
            self.insert(name, native);
        } else {
            self.insert(name, Value::String(redacted));
        }
    }
}

impl Visit for RedactingJsonVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.record_text(field.name(), value);
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        // `%value` and `?value` both land here for most types, so redaction
        // has to happen on the rendered text: it is what the log would have
        // shown, and therefore what the scanner has to see.
        self.record_text(field.name(), format!("{value:?}").trim_matches('"'));
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.record_scalar(field.name(), &value.to_string(), Value::from(value));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.record_scalar(field.name(), &value.to_string(), Value::from(value));
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.record_scalar(field.name(), &value.to_string(), Value::Bool(value));
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.record_text(field.name(), &value.to_string());
    }
}

impl VisitOutput<Result<Map<String, Value>, fmt::Error>> for RedactingJsonVisitor {
    fn finish(self) -> Result<Map<String, Value>, fmt::Error> {
        Ok(self.values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::{Registry, fmt};

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the capture mutex is test-local")
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// Runs `body` through the JSON layer and returns the lines it wrote.
    fn capture(body: impl FnOnce()) -> Vec<Value> {
        let captured = Captured::default();
        let subscriber = Registry::default().with(
            fmt::layer()
                .event_format(RedactingJson)
                .fmt_fields(RedactingJsonFields)
                .with_writer(captured.clone()),
        );
        tracing::subscriber::with_default(subscriber, body);
        let text = String::from_utf8(
            captured
                .0
                .lock()
                .expect("the capture mutex is test-local")
                .clone(),
        )
        .expect("the formatter writes UTF-8");
        text.lines()
            .map(|line| serde_json::from_str(line).expect("every line is JSON"))
            .collect()
    }

    #[test]
    fn an_event_becomes_one_json_object_carrying_its_level_and_target() {
        // Arrange & Act
        let lines = capture(|| tracing::warn!(tenant = "demo", "token refused"));

        // Assert
        assert_eq!(lines.len(), 1);
        let line = &lines[0];
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["target"], module_path!());
        assert_eq!(line["fields"]["message"], "token refused");
        assert_eq!(line["fields"]["tenant"], "demo");
        assert!(line["timestamp"].is_string(), "{line}");
    }

    #[test]
    fn a_secret_field_is_redacted_before_it_reaches_the_json() {
        // Arrange & Act
        let lines = capture(|| tracing::info!(password = "hunter2", "authenticating"));

        // Assert
        let rendered = lines[0]["fields"]["password"]
            .as_str()
            .expect("the field is a string");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.starts_with("[redacted:"), "{rendered}");
    }

    /// The correlation id lives on the span, so it has to travel with the
    /// event or the JSON is a pile of unrelated lines.
    #[test]
    fn the_enclosing_span_and_its_fields_travel_with_the_event() {
        // Arrange & Act
        let lines = capture(|| {
            let span = tracing::info_span!("token", request_id = "01JABCDEF");
            let _entered = span.enter();
            tracing::info!("issued");
        });

        // Assert
        let line = &lines[0];
        assert_eq!(line["span"]["name"], "token");
        assert_eq!(line["span"]["request_id"], "01JABCDEF");
        assert_eq!(line["spans"][0]["name"], "token");
    }

    /// A span field recorded after the span opened must not corrupt the
    /// cached JSON: appending to a serialized object is how that breaks.
    #[test]
    fn a_span_field_recorded_later_keeps_the_object_parseable() {
        // Arrange & Act
        let lines = capture(|| {
            let span = tracing::info_span!(
                "token",
                request_id = "01JABCDEF",
                status = tracing::field::Empty
            );
            let _entered = span.enter();
            span.record("status", 200);
            tracing::info!("issued");
        });

        // Assert
        let line = &lines[0];
        assert_eq!(line["span"]["request_id"], "01JABCDEF");
        assert_eq!(line["span"]["status"], 200);
    }

    /// A number stays a number: a collector that cannot range-query a status
    /// code has lost the point of the format.
    #[test]
    fn an_ordinary_number_keeps_its_json_type() {
        // Arrange & Act
        let lines = capture(|| tracing::info!(status = 404_u64, permanent = false, "swept"));

        // Assert
        assert_eq!(lines[0]["fields"]["status"], 404);
        assert_eq!(lines[0]["fields"]["permanent"], false);
    }
}
