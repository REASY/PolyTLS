use crate::telemetry::TelemetryResult;
use gethostname::gethostname;
use local_ip_address::local_ip;
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_resource_detectors::{OsResourceDetector, ProcessResourceDetector};
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::{
    Aggregation, Instrument, InstrumentKind, PeriodicReader, SdkMeterProvider, Stream,
};
use opentelemetry_sdk::resource::{Resource, ResourceDetector};
use opentelemetry_semantic_conventions::attribute;
use std::time::Duration;

pub struct HostResourceDetector;

impl HostResourceDetector {
    fn get_ip(&self) -> Option<String> {
        local_ip().ok().map(|ip| ip.to_string())
    }

    fn get_hostname(&self) -> Option<String> {
        gethostname().to_str().map(|x| x.to_string())
    }
}

impl ResourceDetector for HostResourceDetector {
    fn detect(&self) -> Resource {
        Resource::builder_empty()
            .with_attributes(vec![KeyValue::new(
                attribute::HOST_NAME,
                self.get_hostname()
                    .unwrap_or_else(|| "#unknown#".to_string()),
            )])
            .with_attributes(vec![KeyValue::new(
                attribute::HOST_IP,
                self.get_ip().unwrap_or_else(|| "#unknown#".to_string()),
            )])
            .build()
    }
}

fn build_resource(service_name: &str) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_string())
        .with_detector(Box::new(OsResourceDetector))
        .with_detector(Box::new(ProcessResourceDetector))
        .with_detector(Box::new(HostResourceDetector))
        .build()
}

pub fn init_logger_provider(service_name: &str) -> TelemetryResult<SdkLoggerProvider> {
    let exporter = opentelemetry_otlp::LogExporter::builder()
        .with_http()
        .build()?;

    let logger_provider = SdkLoggerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(build_resource(service_name))
        .build();
    Ok(logger_provider)
}

pub fn init_meter_provider(
    service_name: &str,
    reader_interval: Duration,
) -> TelemetryResult<SdkMeterProvider> {
    let exporter = opentelemetry_otlp::MetricExporter::builder()
        .with_http()
        .with_protocol(opentelemetry_otlp::Protocol::HttpBinary)
        .with_temporality(opentelemetry_sdk::metrics::Temporality::Delta)
        .build()?;

    let reader = PeriodicReader::builder(exporter)
        .with_interval(reader_interval)
        .build();

    let meter_provider = SdkMeterProvider::builder()
        .with_reader(reader)
        .with_resource(build_resource(service_name))
        .with_view(move |instrument: &Instrument| {
            if matches!(instrument.kind(), InstrumentKind::Histogram) {
                Some(
                    Stream::builder()
                        .with_aggregation(Aggregation::Base2ExponentialHistogram {
                            max_size: 160,
                            max_scale: 20,
                            record_min_max: true,
                        })
                        .build()
                        .expect("failed to build histogram view"),
                )
            } else {
                None
            }
        })
        .build();

    Ok(meter_provider)
}
