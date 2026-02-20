# JoePoints v3.0.2 - Change Log

## Security Fixes

### Hardened client IP detection
* Introduced a new TrustProxyHeaders flag (default: false) in server.go.
* GetClientIP now uses RemoteAddr exclusively unless proxy header trust is explicitly enabled.
* Prevents rate-limit bypass and IP spoofing in non-proxied deployments.

### Validated proxy headers when enabled
* When TrustProxyHeaders is set to true, X-Forwarded-For and X-Real-IP headers are:
    * Parsed using net.ParseIP
    * Accepted only if syntactically valid
* Prevents acceptance of malformed or spoofed IP header values.

## Performance & Concurrency Improvements

### Reduced lock contention in API key validation
* Refactored DBAuthKeyExists in db.go.
    1. Snapshots key rows while holding dbLock.RLock()
    2. Releases the lock
    3. Performs Argon2 hashing outside the lock
* Eliminates long-held read locks during CPU-bound hashing operations.
* Reduces writer starvation and improves database concurrency under load.