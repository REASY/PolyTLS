pub mod logger;
pub mod otlp;

pub type TelemetryResult<T> = std::result::Result<T, crate::error::PolyTlsError>;

pub use logger::setup_logging;
use opentelemetry_sdk::logs::SdkLoggerProvider;
pub use otlp::{init_logger_provider, init_meter_provider};
use tracing::level_filters::LevelFilter;

pub fn init_otlp_logging(
    service_name: &str,
    default_level: LevelFilter,
    crate_filters: &[&str],
) -> TelemetryResult<SdkLoggerProvider> {
    let provider = init_logger_provider(service_name)?;
    setup_logging(default_level, &provider, crate_filters)?;
    Ok(provider)
}
