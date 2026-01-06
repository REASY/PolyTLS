# Fingerprint capture data

This folder contains captured TLS fingerprint JSON outputs from https://tls.peet.ws/api/all used when comparing PolyTLS against real browsers (JA3/JA4/extension sets, ordering, etc).

## Layout
- `real/`: captured from a real browser directly (no proxy in the path).
- `via-polytls/`: captured when the client connects through PolyTLS.
