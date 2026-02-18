# JoePoints v3.0.1 - Change Log

## Security Fixes

### Rate Limiter Proxy Support
* **Fixed rate limiter ineffectiveness when behind reverse proxy**
* `GetClientIP()` now checks `X-Forwarded-For` and `X-Real-IP` headers before falling back to `RemoteAddr`
* Properly extracts original client IP when behind proxies like nginx, Cloudflare, or other reverse proxies
* Prevents all clients appearing as the same IP (the proxy's IP) which made rate limiting useless

## Multithreading Improvements and Fixes

### Race Condition in Point Addition
* **Fixed critical race condition in `handleAddpoints`** where overflow/underflow checks occurred outside the database lock
* Moved bounds checking into `DBAddPoints()` function where it's protected by the lock
* Prevents TOCTOU (Time-of-Check-Time-of-Use) vulnerability that could allow point overflows
* Overflow/underflow validation now happens atomically with the database update

### Deadlock Prevention
* **Fixed potential deadlock in `DBAuthKeyExists`**
* Removed nested `db.QueryRow()` call that could exhaust connection pool while holding read lock
* Now fetches all required columns (`key_hash`, `salt`, `argon2_time_cost`, `argon2_memory_kb`, `argon2_threads`) in single query
* Eliminates risk of deadlock from connection pool exhaustion

### Server Lifecycle Management
* **Added `serverLock` mutex** to protect global `server` variable from concurrent access in `StartServer()` and `StopServer()`
* **Fixed goroutine leak** in `cleanupIPTable()` - cleanup goroutine now properly terminates on shutdown
* Added `cleanupDone` channel with select statement for graceful goroutine termination
* **Added `sync.Once` to `StopServer()`** to prevent panic from closing `cleanupDone` channel multiple times
* **Switched from `server.Close()` to `server.Shutdown()`** for graceful shutdown with 5-second timeout
* Ensures active HTTP handlers complete before database cleanup

### Database Thread Safety
* **Added lock protection to `DBClose()`** to handle edge case where `server.Shutdown()` timeout expires with active handlers still running
* Prevents race condition between lingering handlers and database cleanup

## Current vulnerabilities

### Replay Attacks
* **Endpoints vulnerable to replay attacks** due to lack of any repeat request protection
* OAuth2.0 and nonces will be impliemented in the v4.0 release to mitigate this issue
* For now, ensure use with https reverse proxy to lessen the issue