use std::borrow::Cow;

use kube::ResourceExt;
use opentelemetry::trace::TraceId;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, exemplar::HistogramWithExemplars, family::Family},
    registry::Unit,
};
use tokio::time::Instant;

use crate::{Error, metrics};

#[derive(Clone)]
pub struct ControllerMetrics {
    pub runs: Family<ControllerLabels, Counter>,
    pub failures: Family<ErrorLabels, Counter>,
    pub duration: HistogramWithExemplars<TraceLabel>,
}

impl ControllerMetrics {
    /// Register API metrics to start tracking them.
    pub fn new(controller_name: &str) -> Self {
        let mut guard = metrics::REGISTRY.write().unwrap();
        let registry = guard.sub_registry_with_label((
            Cow::Borrowed("controller_name"),
            Cow::Owned(controller_name.into()),
        ));
        let runs = Family::<ControllerLabels, Counter>::default();
        let failures = Family::<ErrorLabels, Counter>::default();
        let duration =
            HistogramWithExemplars::new([0.01, 0.1, 0.25, 0.5, 1.0, 5.0, 15.0, 60.0].into_iter());

        registry.register_with_unit(
            "reconcile_duration",
            "reconcile duration",
            Unit::Seconds,
            duration.clone(),
        );
        registry.register(
            "reconcile_failures",
            "Number of reconciliation errors",
            failures.clone(),
        );
        registry.register("reconcile_runs", "Number of reconciliations", runs.clone());
        Self {
            runs,
            failures,
            duration,
        }
    }

    pub fn count_failure<K>(&self, _k: &K, e: &Error)
    where
        K: ResourceExt<DynamicType = ()>,
    {
        self.failures
            .get_or_create(&ErrorLabels {
                resource: K::kind(&()).into_owned().to_lowercase(),
                error: e.metric_label(),
            })
            .inc();
    }

    pub fn count_and_measure<K>(&self, _k: &K, trace_id: &TraceId) -> ReconcileMeasurer
    where
        K: ResourceExt<DynamicType = ()>,
    {
        self.runs
            .get_or_create(&ControllerLabels {
                resource: K::kind(&()).into_owned().to_lowercase(),
            })
            .inc();
        ReconcileMeasurer {
            start: Instant::now(),
            labels: trace_id.try_into().ok(),
            metric: self.duration.clone(),
        }
    }
}

pub struct ReconcileMeasurer {
    start: Instant,
    labels: Option<TraceLabel>,
    metric: HistogramWithExemplars<TraceLabel>,
}

impl Drop for ReconcileMeasurer {
    fn drop(&mut self) {
        #[allow(clippy::cast_precision_loss)]
        let duration = self.start.elapsed().as_millis() as f64 / 1000.0;
        let labels = self.labels.take();
        self.metric.observe(duration, labels);
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ControllerLabels {
    pub resource: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct ErrorLabels {
    pub resource: String,
    pub error: String,
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
