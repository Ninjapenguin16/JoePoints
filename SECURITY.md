# Security Vulnerabilities & Fixes

## Identified Vulnerabilities

### 1. **CORS Wildcard Configuration** ✅ INTENTIONAL
**Severity:** MEDIUM (Accepted by Design)
- **Why It's There:** Authenticated users are expected to access from various sources and subnets
- **Risk Mitigation:** Bearer token authentication required for all state-changing operations
- **Design Decision:** For a multi-environment application where authenticated users may come from different networks/subnets, wildcard CORS is appropriate since the real security is the bearer token, not the origin
- **Note:** If deployment changes and origin restriction becomes necessary, use:
  ```go
  allowedOrigin := os.Getenv("ALLOWED_ORIGIN")
  if allowedOrigin == "" {
    allowedOrigin = "*"
  }
  w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
  ```

### 2. **Trusted X-Forwarded-For Header** ✅ FIXED
**Severity:** MEDIUM
- **Issue:** Rate limiting based on X-Forwarded-For header which clients can spoof
- **Risk:** Rate limit bypass from distributed attacks
- **Fix:** Now uses RemoteAddr (direct connection) instead
- **Note:** If behind a reverse proxy, configure trusted proxies explicitly or add:
  ```go
  // For trusted proxies only
  if isTrustedProxy(r) {
    ip := r.Header.Get("X-Forwarded-For")
    return strings.Split(ip, ",")[0]
  }
  ```

### 3. **JSON Decoder Size Limit** ✅ FIXED
**Severity:** MEDIUM
- **Issue:** `json.NewDecoder` without size limit could cause DoS with large payloads
- **Risk:** Memory exhaustion attacks
- **Fix:** Added `io.LimitReader` with `MaxBodySize` limit (16KB)
- **Implementation:** `io.LimitReader(r.Body, int64(MaxBodySize))`

## Remaining Vulnerabilities & Mitigations

### Architecture Notes
- **TLS/HTTPS:** NOT included by design; expected to be deployed behind a reverse proxy
- **CORS:** Wildcard allowed by design for multi-source authenticated access
- **Rate Limiting:** 30 req/15sec appropriate for human-only interaction

### 4. **CSRF Token Protection - Not Needed** ✅ INTENTIONALLY OMITTED
**Severity:** N/A (Not applicable)
- **Why Not Needed:** CSRF protection is primarily for session cookie-based authentication
- **This Application:** Uses Bearer token authentication in the Authorization header
- **Browser Security:** Browsers do not automatically send Authorization headers cross-origin; they enforce Same-Origin Policy
- **Result:** A malicious website cannot trick a user's browser into making authenticated requests to this API
- **Conclusion:** CSRF tokens are redundant when using proper Bearer token authentication

### 5. **Rate Limiting - 30 req/15 seconds** ✅ APPROPRIATE
**Severity:** LOW
- **Design:** 30 requests per 15 seconds is intentional for human-only interaction
- **Justification:** This application expects human-driven requests only, not automated bulk operations
- **Current Status:** IP-based limiting per client
- **Assessment:** Adequate for single-user/small-team deployments
- **Future Enhancement:** If multi-tenant with many concurrent users, consider:
  - Per-API-key rate limiting for authenticated endpoints
  - Adaptive limits based on observed patterns

### 6. **Request Timeout for Slow Reads** ✅ UPDATED
**Severity:** LOW-MEDIUM
- **Issue:** Slow-read attacks could tie up connections
- **Previous:** `ConnectionTimeout = 10 seconds`
- **Updated to:** `ConnectionTimeout = 5 seconds`
- **Implementation:** All read, write, and idle timeouts now set to 5 seconds

### 7. **Insufficient Input Validation on Names** ✅ ADDED
**Severity:** LOW
- **Issue:** First/last names accept any printable Unicode, including emojis, RTL characters
- **Fix:** Added `validateName()` function in api.go
- **Validates:** 
  - Length: 1-100 characters
  - Rejects control characters (except tab)
  - Rejects HTML/XML tags: `< > " & ;`
- **Implementation:** `validateName()` checks all input names before database operations

### 8. **Audit Logging - Important for Multi-User Environments** ✅ IMPLEMENTED
**Severity:** MEDIUM
- **Implementation:** Using `slog` structured logging to stdout
- **Rate Limit Logging:** Only logs FIRST violation per IP per time window (prevents log spam)
- **Audit Events Logged:**
  - `KEY_CREATED` - when new API key is generated
  - `USER_ADDED` - when new user added (with uid and name)
  - `USER_REMOVED` - when user deleted
  - `POINTS_SET` - when points are explicitly set
  - `POINTS_ADDED` - when points are incremented/decremented
  - `KEY_REMOVED` - when API key is revoked
  - `AUTH_FAILED` - when invalid API key is used (logs IP address)
  - `RATE_LIMIT_EXCEEDED` - once per IP per rate limit window
- **Log Format:** Structured JSON via `slog.Info()` with action, API key prefix, and details
- **Docker Integration:** Logs go to stdout (captured by Docker automatically)
- **Sample Output:**
  ```
  time=2026-01-21T10:30:45.123Z level=INFO msg=AUDIT action=KEY_CREATED apiKey=abc12345... details=identifier=user_one
  time=2026-01-21T10:30:46.456Z level=INFO msg=AUDIT action=USER_ADDED apiKey=abc12345... details=uid=1 name=John Doe
  time=2026-01-21T10:30:47.789Z level=WARN msg=RATE_LIMIT_EXCEEDED ip=192.168.1.100 requestCount=31 limit=30
  ```

### 9. **API Key Management** ✅ BY DESIGN
**Severity:** N/A
- **No Key Rotation:** Keys are single-use (issued once)
- **Key Replacement:** Only changed if owner confirms token compromise
- **Revocation:** `handleRemovekey()` allows key owner to revoke their own key
- **Design Decision:** Reduces operational complexity while maintaining security for low-frequency human-driven access

### 10. **Silent Failures on Errors** ✅ ADDRESSED
**Severity:** LOW
- **Status:** All DB operations already return errors to endpoints
- **Verification:** Checked api.go handlers - all DB errors are checked:
  - `DBAddUser()` error returned to client
  - `DBSetPoints()` error returned to client
  - `DBAddPoints()` error returned to client
  - `DBRemoveKey()` error returned to client
- **All errors result in 500 Internal Server Error response to client**

## Recently Implemented Security Improvements (This Session)

- ✅ **Audit Logging:** All sensitive operations logged via `slog` to stdout
- ✅ **Input Validation:** Added `validateName()` for first/last name validation
- ✅ **Request Timeout:** Reduced from 10s to 5s to mitigate slow-read attacks
- ✅ **Rate Limit Logging:** Only logs first violation per IP per window (prevents log spam)
- ✅ **Error Handling:** Verified all DB operations properly return errors

- **SQL Injection:** Parameterized queries prevent SQL injection ✅
- **Path Traversal:** `filepath.Clean()` and boundary checks prevent directory traversal ✅
- **Cryptography:** PBKDF2-HMAC-SHA256 with 100,000 iterations for key hashing ✅
- **Authentication:** All sensitive endpoints require valid API key ✅
- **Memory Safety:** Go's automatic bounds checking prevents buffer overflows ✅
- **Random Generation:** Cryptographically secure random number generation ✅
- **Body Size Limits:** Request body size limited to 16KB ✅
- **Header Size Limits:** Max header size 8KB ✅
- **Connection Limits:** Max 100 concurrent connections ✅
- **Request Timeouts:** 5-second read/write/idle timeouts ✅
- **Audit Logging:** All sensitive operations logged via structured logging ✅
- **Input Validation:** Names validated to reject control characters and HTML ✅

## Configuration Best Practices

### Environment-Specific Settings
```go
// In main.go or init
if os.Getenv("ENV") == "production" {
  // Stricter limits
  MaxRequestsPerIP = 15
  RateLimitWindow = 30 * time.Second
  // Restrict CORS
  allowedOrigin = "https://yourdomain.com"
}
```

### Required for Production
1. Enable HTTPS/TLS (currently missing)
2. Set restrictive rate limits based on actual usage
3. Configure audit logging
4. Set up monitoring/alerting
5. Regular security audits
6. Implement CSRF tokens for web clients

## Deployment Checklist

- [x] CORS wildcard intentional for multi-source authenticated access
- [x] Audit logging implemented (stdout, no file management needed)
- [x] Input validation for names implemented
- [x] Request timeout reduced to 5 seconds
- [ ] Deploy behind reverse proxy (nginx/Caddy) for TLS/HTTPS
- [x] Rate limits appropriate for human-only interaction (30 req/15sec)
- [ ] Regular backups of `data.db`
- [ ] File permissions on `data.db` restricted (mode 0600)
- [ ] Monitor audit logs for suspicious activity