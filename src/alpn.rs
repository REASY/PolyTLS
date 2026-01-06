use std::fmt;

/// IANA registered ALPN protocol IDs.
/// Source: <https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids>
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AlpnProtocol {
    /// "http/0.9": HTTP/0.9
    Http09,
    /// "http/1.0": HTTP/1.0
    Http10,
    /// "http/1.1": HTTP/1.1
    Http11,
    /// "spdy/1": SPDY/1
    Spdy1,
    /// "spdy/2": SPDY/2
    Spdy2,
    /// "spdy/3": SPDY/3
    Spdy3,
    /// "stun.turn": Traversal Using Relays around NAT (TURN)
    StunTurn,
    /// "stun.nat-discovery": NAT discovery using Session Traversal Utilities for NAT (STUN)
    StunNatDiscovery,
    /// "h2": HTTP/2 over TLS
    H2,
    /// "h2c": HTTP/2 over TCP
    H2c,
    /// "webrtc": WebRTC Media and Data
    Webrtc,
    /// "c-webrtc": Confidential WebRTC Media and Data
    CWebrtc,
    /// "ftp": FTP
    Ftp,
    /// "imap": IMAP
    Imap,
    /// "pop3": POP3
    Pop3,
    /// "manage": Manage
    Manage,
    /// "coap": CoAP
    Coap,
    /// "xmpp-client": XMPP jabber:client namespace
    XmppClient,
    /// "xmpp-server": XMPP jabber:server namespace
    XmppServer,
    /// "acme-tls/1": ACME-TLS/1
    AcmeTls1,
    /// "mqtt": OASIS Message Queuing Telemetry Transport (MQTT)
    Mqtt,
    /// "dot": DNS-over-TLS
    Dot,
    /// "nts/1": Network Time Security Key Establishment
    Nts1,
    /// "sunrpc": SunRPC
    SunRpc,
    /// "h3": HTTP/3
    H3,
    /// "smb": SMB
    Smb,
    /// "irc": IRC
    Irc,
    /// "nntp": NNTP
    Nntp,
    /// "nnsp": NNSP
    Nnsp,
    /// "doq": DNS over QUIC
    Doq,
    /// "sip/2": SIP/2
    Sip2,
    /// "tds/8.0": TDS/8.0
    Tds8,
    /// "dicom": DICOM
    Dicom,
    /// "quic": QUIC
    Quic,
    /// "http/2+quic/43": HTTP/2 over QUIC
    H2Quic43,
    /// "h3-29": HTTP/3 Draft 29
    H3Draft29,
    /// "h3-30": HTTP/3 Draft 30
    H3Draft30,
    /// "h3-31": HTTP/3 Draft 31
    H3Draft31,
    /// "h3-32": HTTP/3 Draft 32
    H3Draft32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownAlpnProtocol {
    bytes: Vec<u8>,
}

impl UnknownAlpnProtocol {
    #[allow(dead_code)]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for UnknownAlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unknown ALPN protocol: {}",
            String::from_utf8_lossy(&self.bytes)
        )
    }
}

impl std::error::Error for UnknownAlpnProtocol {}

impl AlpnProtocol {
    /// Parses a byte slice into an `AlpnProtocol`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, UnknownAlpnProtocol> {
        let protocol = match bytes {
            b"http/0.9" => Self::Http09,
            b"http/1.0" => Self::Http10,
            b"http/1.1" => Self::Http11,
            b"spdy/1" => Self::Spdy1,
            b"spdy/2" => Self::Spdy2,
            b"spdy/3" => Self::Spdy3,
            b"stun.turn" => Self::StunTurn,
            b"stun.nat-discovery" => Self::StunNatDiscovery,
            b"h2" => Self::H2,
            b"h2c" => Self::H2c,
            b"webrtc" => Self::Webrtc,
            b"c-webrtc" => Self::CWebrtc,
            b"ftp" => Self::Ftp,
            b"imap" => Self::Imap,
            b"pop3" => Self::Pop3,
            b"manage" => Self::Manage,
            b"coap" => Self::Coap,
            b"xmpp-client" => Self::XmppClient,
            b"xmpp-server" => Self::XmppServer,
            b"acme-tls/1" => Self::AcmeTls1,
            b"mqtt" => Self::Mqtt,
            b"dot" => Self::Dot,
            b"nts/1" => Self::Nts1,
            b"sunrpc" => Self::SunRpc,
            b"h3" => Self::H3,
            b"smb" => Self::Smb,
            b"irc" => Self::Irc,
            b"nntp" => Self::Nntp,
            b"nnsp" => Self::Nnsp,
            b"doq" => Self::Doq,
            b"sip/2" => Self::Sip2,
            b"tds/8.0" => Self::Tds8,
            b"dicom" => Self::Dicom,
            // Common unofficial/draft values
            b"quic" => Self::Quic,
            b"http/2+quic/43" => Self::H2Quic43,
            b"h3-29" => Self::H3Draft29,
            b"h3-30" => Self::H3Draft30,
            b"h3-31" => Self::H3Draft31,
            b"h3-32" => Self::H3Draft32,
            _ => {
                return Err(UnknownAlpnProtocol {
                    bytes: bytes.to_vec(),
                });
            }
        };
        Ok(protocol)
    }

    /// Returns the canonical byte representation of the protocol ID.
    pub const fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Http09 => b"http/0.9",
            Self::Http10 => b"http/1.0",
            Self::Http11 => b"http/1.1",
            Self::Spdy1 => b"spdy/1",
            Self::Spdy2 => b"spdy/2",
            Self::Spdy3 => b"spdy/3",
            Self::StunTurn => b"stun.turn",
            Self::StunNatDiscovery => b"stun.nat-discovery",
            Self::H2 => b"h2",
            Self::H2c => b"h2c",
            Self::Webrtc => b"webrtc",
            Self::CWebrtc => b"c-webrtc",
            Self::Ftp => b"ftp",
            Self::Imap => b"imap",
            Self::Pop3 => b"pop3",
            Self::Manage => b"manage",
            Self::Coap => b"coap",
            Self::XmppClient => b"xmpp-client",
            Self::XmppServer => b"xmpp-server",
            Self::AcmeTls1 => b"acme-tls/1",
            Self::Mqtt => b"mqtt",
            Self::Dot => b"dot",
            Self::Nts1 => b"nts/1",
            Self::SunRpc => b"sunrpc",
            Self::H3 => b"h3",
            Self::Smb => b"smb",
            Self::Irc => b"irc",
            Self::Nntp => b"nntp",
            Self::Nnsp => b"nnsp",
            Self::Doq => b"doq",
            Self::Sip2 => b"sip/2",
            Self::Tds8 => b"tds/8.0",
            Self::Dicom => b"dicom",
            Self::Quic => b"quic",
            Self::H2Quic43 => b"http/2+quic/43",
            Self::H3Draft29 => b"h3-29",
            Self::H3Draft30 => b"h3-30",
            Self::H3Draft31 => b"h3-31",
            Self::H3Draft32 => b"h3-32",
        }
    }
}

impl fmt::Display for AlpnProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes = self.as_bytes();
        // Best-effort string representation
        write!(f, "{}", String::from_utf8_lossy(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_variants_round_trip() {
        let cases = vec![
            (AlpnProtocol::Http11, b"http/1.1".as_slice()),
            (AlpnProtocol::H2, b"h2"),
            (AlpnProtocol::Http10, b"http/1.0"),
            (AlpnProtocol::H2c, b"h2c"),
            (AlpnProtocol::Quic, b"quic"),
            (AlpnProtocol::H3Draft29, b"h3-29"),
        ];

        for (proto, bytes) in cases {
            assert_eq!(
                AlpnProtocol::from_bytes(bytes).expect("should parse known ALPN"),
                proto
            );
            assert_eq!(proto.as_bytes(), bytes);
            assert_eq!(format!("{}", proto), String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn test_unknown_protocol() {
        let bytes = b"custom-protocol";
        let err = AlpnProtocol::from_bytes(bytes).expect_err("should reject unknown ALPN");
        assert_eq!(err.bytes(), bytes);
    }

    #[test]
    fn test_empty_bytes() {
        let bytes = b"";
        let err = AlpnProtocol::from_bytes(bytes).expect_err("empty ALPN must be rejected");
        assert_eq!(err.bytes(), bytes);
    }

    #[test]
    fn test_non_utf8_display() {
        // Some hypothetical binary protocol identifier
        let bytes = b"\xff\xfe\x00\x01";
        let err = AlpnProtocol::from_bytes(bytes).expect_err("should reject non-UTF8 ALPN");
        assert_eq!(err.bytes(), bytes);
        let display = format!("{err}");
        assert!(display.contains('\u{FFFD}')); // Replacement character
    }
}
