use opentelemetry::TraceId;
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::exemplar::HistogramWithExemplars;
use prometheus_client::metrics::family::Family;
use prometheus_client::registry::{Registry, Unit};

use crate::Error;

#[derive(Clone)]
pub struct ControllerMetrics {
    pub inserts: Family<InsertLabels, Counter>,
    pub duration: HistogramWithExemplars<TraceLabel>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct InsertLabels {
    pub table: String,
    pub status: String,
}

impl Default for ControllerMetrics {
    fn default() -> Self {
        Self {
            inserts: Family::<InsertLabels, Counter>::default(),
            duration: HistogramWithExemplars::new(
                [0.01, 0.1, 0.25, 0.5, 1.0, 5.0, 15.0, 60.0].into_iter(),
            ),
        }
    }
}

impl ControllerMetrics {
    /// Register API metrics to start tracking them.
    pub fn register(self, r: &mut Registry) -> Self {
        r.register_with_unit(
            "insert_duration",
            "reconcile duration",
            Unit::Seconds,
            self.duration.clone(),
        );
        r.register(
            "inserts",
            "Number of bpf table inserts",
            self.inserts.clone(),
        );
        self
    }
}

#[derive(Clone, Hash, PartialEq, Eq, EncodeLabelSet, Debug, Default)]
pub struct TraceLabel {
    pub trace_id: String,
}
impl TryFrom<&TraceId> for TraceLabel {
    type Error = crate::Error;

    fn try_from(id: &TraceId) -> Result<TraceLabel, Self::Error> {
        if std::matches!(id, &TraceId::INVALID) {
            Err(Error::ConversionError(
                "failed to convert trace id to label".into(),
            ))
        } else {
            let trace_id = id.to_string();
            Ok(Self { trace_id })
        }
    }
}
pub fn get_trace_id() -> TraceId {
    use opentelemetry::trace::TraceContextExt as _; // opentelemetry::Context -> opentelemetry::trace::Span
    use tracing_opentelemetry::OpenTelemetrySpanExt as _; // tracing::Span to opentelemetry::Context
    tracing::Span::current()
        .context()
        .span()
        .span_context()
        .trace_id()
}
