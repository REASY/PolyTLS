use crate::error::{ErrorKind, Result};
use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor, SslContextBuilder};
use foreign_types::ForeignType;
use std::collections::HashSet;
use std::io;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CertCompression {
    Zlib,
    Brotli,
    Zstd,
}

impl CertCompression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zlib => "zlib",
            Self::Brotli => "brotli",
            Self::Zstd => "zstd",
        }
    }
}

pub fn parse_cert_compression_list(values: &[String]) -> Result<Vec<CertCompression>> {
    let mut out = Vec::with_capacity(values.len());
    let mut seen = HashSet::new();

    for raw in values {
        let name = raw.trim().to_ascii_lowercase();
        let alg = match name.as_str() {
            "zlib" => CertCompression::Zlib,
            "brotli" => CertCompression::Brotli,
            "zstd" => CertCompression::Zstd,
            other => {
                return Err(ErrorKind::Config(format!(
                    "unknown cert_compression algorithm {other:?} (expected zlib, brotli, zstd)"
                ))
                .into());
            }
        };

        if !seen.insert(alg) {
            return Err(ErrorKind::Config(format!(
                "duplicate cert_compression algorithm {name:?}"
            ))
            .into());
        }

        out.push(alg);
    }

    Ok(out)
}

pub fn register_certificate_compression(
    builder: &mut SslContextBuilder,
    algorithms: &[CertCompression],
) -> Result<()> {
    let mut seen = HashSet::new();
    for alg in algorithms {
        if !seen.insert(*alg) {
            return Err(ErrorKind::Config(format!(
                "duplicate cert_compression algorithm {:?}",
                alg.as_str()
            ))
            .into());
        }
    }

    for alg in algorithms {
        match alg {
            CertCompression::Zlib => builder
                .add_certificate_compression_algorithm(ZlibCertDecompressor)
                .map_err(|e| {
                    ErrorKind::Config(format!("failed to add zlib cert compression: {e}"))
                })?,
            CertCompression::Brotli => builder
                .add_certificate_compression_algorithm(BrotliCertDecompressor)
                .map_err(|e| {
                    ErrorKind::Config(format!("failed to add brotli cert compression: {e}"))
                })?,
            CertCompression::Zstd => register_zstd_cert_decompressor(builder)?,
        }
    }

    Ok(())
}

#[derive(Clone, Copy, Default)]
struct ZlibCertDecompressor;

impl CertificateCompressor for ZlibCertDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        let mut decoder = flate2::read::ZlibDecoder::new(std::io::Cursor::new(input));
        std::io::copy(&mut decoder, output)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Default)]
pub struct BrotliCertDecompressor;

impl CertificateCompressor for BrotliCertDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
    where
        W: io::Write,
    {
        brotli::BrotliDecompress(&mut std::io::Cursor::new(input), output)?;
        Ok(())
    }
}

fn register_zstd_cert_decompressor(builder: &mut SslContextBuilder) -> Result<()> {
    let success = unsafe {
        boring_sys::SSL_CTX_add_cert_compression_alg(
            builder.as_ptr(),
            3,
            None,
            Some(raw_ssl_cert_decompress_zstd),
        ) == 1
    };

    if !success {
        return Err(ErrorKind::Config(
            "failed to add zstd cert decompression algorithm".to_string(),
        )
        .into());
    }

    Ok(())
}

foreign_types::foreign_type! {
    unsafe type CryptoBuffer {
        type CType = boring_sys::CRYPTO_BUFFER;
        fn drop = boring_sys::CRYPTO_BUFFER_free;
    }
}

unsafe extern "C" fn raw_ssl_cert_decompress_zstd(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut boring_sys::CRYPTO_BUFFER,
    uncompressed_len: usize,
    input: *const u8,
    input_len: usize,
) -> ::std::os::raw::c_int {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out.is_null() {
            return 0;
        }
        unsafe {
            *out = std::ptr::null_mut();
        }

        if uncompressed_len == 0 {
            return 0;
        }
        if input.is_null() && input_len != 0 {
            return 0;
        }

        let input_slice = if input_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(input, input_len) }
        };

        let mut data: *mut u8 = std::ptr::null_mut();
        let buffer = unsafe { boring_sys::CRYPTO_BUFFER_alloc(&mut data, uncompressed_len) };
        if buffer.is_null() {
            return 0;
        }
        let buffer = unsafe { CryptoBuffer::from_ptr(buffer) };
        if data.is_null() {
            return 0;
        }

        let output_slice = unsafe { std::slice::from_raw_parts_mut(data, uncompressed_len) };
        let written = match zstd::bulk::decompress_to_buffer(input_slice, output_slice) {
            Ok(n) => n,
            Err(_) => return 0,
        };

        if written != uncompressed_len {
            return 0;
        }

        unsafe { *out = buffer.into_ptr() };
        1
    }));

    result.unwrap_or_else(|_| 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    // `scudo` currently doesn't build on macOS (scudo-standalone lacks a Darwin
    // platform implementation), so we only enable it on Linux for hardening
    // these tests.
    #[cfg(target_os = "linux")]
    #[global_allocator]
    static SCUDO_ALLOCATOR: scudo::GlobalScudoAllocator = scudo::GlobalScudoAllocator;

    #[test]
    fn raw_ssl_cert_decompress_zstd_roundtrip() {
        let plain = b"polytls-zstd-cert-decompression-test";
        let compressed = zstd::bulk::compress(plain, 0).unwrap();

        let mut out: *mut boring_sys::CRYPTO_BUFFER = ptr::null_mut();
        let rc = unsafe {
            raw_ssl_cert_decompress_zstd(
                ptr::null_mut(),
                &mut out,
                plain.len(),
                compressed.as_ptr(),
                compressed.len(),
            )
        };

        assert_eq!(rc, 1);
        assert!(!out.is_null());

        let out_len = unsafe { boring_sys::CRYPTO_BUFFER_len(out) };
        assert_eq!(out_len, plain.len());

        let out_ptr = unsafe { boring_sys::CRYPTO_BUFFER_data(out) };
        assert!(!out_ptr.is_null());
        let out_slice = unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
        assert_eq!(out_slice, plain);

        unsafe { boring_sys::CRYPTO_BUFFER_free(out) };
    }

    #[test]
    fn raw_ssl_cert_decompress_zstd_exhaustive_matrix() {
        #[derive(Clone, Copy, Debug)]
        enum Payload {
            Valid,
            Invalid,
        }

        let plain = b"polytls-zstd-cert-decompression-test";
        let compressed_valid = zstd::bulk::compress(plain, 0).unwrap();
        let mut compressed_invalid = compressed_valid.clone();
        if let Some(first) = compressed_invalid.first_mut() {
            *first ^= 0xff;
        }

        for out_is_null in [true, false] {
            for uncompressed_len in [
                0,
                plain.len(),
                plain.len().saturating_sub(1),
                plain.len() + 1,
            ] {
                for input_is_null in [true, false] {
                    for input_len in [0usize, compressed_valid.len()] {
                        for payload in [Payload::Valid, Payload::Invalid] {
                            let buf = match payload {
                                Payload::Valid => compressed_valid.as_slice(),
                                Payload::Invalid => compressed_invalid.as_slice(),
                            };

                            let input_ptr = if input_is_null {
                                ptr::null()
                            } else {
                                buf.as_ptr()
                            };
                            let effective_input_len = input_len.min(buf.len());

                            if out_is_null {
                                let rc = unsafe {
                                    raw_ssl_cert_decompress_zstd(
                                        ptr::null_mut(),
                                        ptr::null_mut(),
                                        uncompressed_len,
                                        input_ptr,
                                        effective_input_len,
                                    )
                                };
                                assert_eq!(
                                    rc, 0,
                                    "expected early failure with null out, case={out_is_null:?} {uncompressed_len} {input_is_null:?} {effective_input_len} {payload:?}"
                                );
                                continue;
                            }

                            let mut out_buf: *mut boring_sys::CRYPTO_BUFFER = 1usize as *mut _;
                            let rc = unsafe {
                                raw_ssl_cert_decompress_zstd(
                                    ptr::null_mut(),
                                    &mut out_buf,
                                    uncompressed_len,
                                    input_ptr,
                                    effective_input_len,
                                )
                            };

                            let expect_success = uncompressed_len == plain.len()
                                && !input_is_null
                                && effective_input_len == compressed_valid.len()
                                && matches!(payload, Payload::Valid);

                            if expect_success {
                                assert_eq!(
                                    rc, 1,
                                    "case={out_is_null:?} {uncompressed_len} {input_is_null:?} {effective_input_len} {payload:?}"
                                );
                                assert!(
                                    !out_buf.is_null(),
                                    "expected out buffer on success, case={out_is_null:?} {uncompressed_len} {input_is_null:?} {effective_input_len} {payload:?}"
                                );
                                let out_len = unsafe { boring_sys::CRYPTO_BUFFER_len(out_buf) };
                                assert_eq!(out_len, plain.len());
                                let out_ptr = unsafe { boring_sys::CRYPTO_BUFFER_data(out_buf) };
                                assert!(!out_ptr.is_null());
                                let out_slice =
                                    unsafe { std::slice::from_raw_parts(out_ptr, out_len) };
                                assert_eq!(out_slice, plain);
                                unsafe { boring_sys::CRYPTO_BUFFER_free(out_buf) };
                            } else {
                                assert_eq!(
                                    rc, 0,
                                    "case={out_is_null:?} {uncompressed_len} {input_is_null:?} {effective_input_len} {payload:?}"
                                );
                                assert!(
                                    out_buf.is_null(),
                                    "expected *out to be cleared on failure, case={out_is_null:?} {uncompressed_len} {input_is_null:?} {effective_input_len} {payload:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
