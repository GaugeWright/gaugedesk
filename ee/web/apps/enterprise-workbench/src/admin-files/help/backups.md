# Backups

Tenant-held public recipients, schedule, retention, and sealed restore-point
metadata. Private recovery material never enters this Environment.

Restore is a two-review handshake. Begin restore mints a deterministic,
one-time receiver public key for an erased managed Machine. A retained recovery
holder unwraps the point key locally and re-wraps it to that receiver. Complete
restore admits only the exact point, receiver id, and opaque receiver wrap.
Exact retries return the original result; changed intent fails closed. The Hub
never receives a recovery private key or plaintext point key.
