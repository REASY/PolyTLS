use crate::error::{ErrorKind, PolyTlsError};
use crate::telemetry::TelemetryResult;
use opentelemetry_appender_tracing::layer;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use std::env;
use tracing::info;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::{EnvFilter, layer::Layer, prelude::*};

pub fn setup_logging(
    default_level: LevelFilter,
    provider: &SdkLoggerProvider,
    crate_filters: &[&str],
) -> TelemetryResult<()> {
    if env::var_os("RUST_LOG").is_none() {
        let mut entries: Vec<String> = crate_filters
            .iter()
            .map(|name| format!("{name}={default_level}"))
            .collect();
        entries.push("tower_http=WARN".to_string());
        entries.push("hyper=WARN".to_string());
        unsafe {
            env::set_var("RUST_LOG", entries.join(","));
        }
    }
    init_logger(provider, default_level)
}

pub fn init_logger(
    provider: &SdkLoggerProvider,
    default_level: LevelFilter,
) -> TelemetryResult<()> {
    let filter_otel = EnvFilter::new(default_level.to_string())
        .add_directive(parse_directive("hyper=off")?)
        .add_directive(parse_directive("tonic=off")?)
        .add_directive(parse_directive("h2=off")?)
        .add_directive(parse_directive("reqwest=off")?);
    let otel_layer = layer::OpenTelemetryTracingBridge::new(provider).with_filter(filter_otel);

    let filter_fmt = EnvFilter::new(default_level.to_string())
        .add_directive(parse_directive("opentelemetry=info")?);
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_filter(filter_fmt);

    tracing_subscriber::registry()
        .with(otel_layer)
        .with(fmt_layer)
        .try_init()
        .map_err(|err| PolyTlsError::new(ErrorKind::TracingSubscriberError(err.to_string())))?;

    info!("Logger initialized");
    Ok(())
}

fn parse_directive(spec: &str) -> TelemetryResult<Directive> {
    spec.parse::<Directive>()
        .map_err(|err| PolyTlsError::new(ErrorKind::TracingSubscriberError(err.to_string())))
}
