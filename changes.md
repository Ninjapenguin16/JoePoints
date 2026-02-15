# JoePoints v3.0 - Change Log

## Major Security & API Improvements

* API keys are now immediately hashed upon receipt using Argon2ID; raw keys are zeroed in memory to minimize exposure.
* Argon2ID parameters (time, memory, threads) are stored with each hashed key in the database.
* DB functions now only accept hashed API keys: `DBAddKey`, `DBRemoveKey`, `DBCheckAuth`; `DBAuthKeyExists` returns the hashed key for use in other DB functions.
* Hashed API keys are printed in logs instead of raw keys.
* New DB function and API endpoint added for retrieving a hashed key's identifier.
* Password hashing and API key handling now fully compliant with updated security practices.
* Strong CSP implemented across all pages; websites updated to comply.
* Additional HTTP headers added for security:

  * `X-Content-Type-Options: nosniff`
  * `X-Frame-Options: DENY`
  * `Referrer-Policy: strict-origin-when-cross-origin`
  * `Permissions-Policy` configured to minimize browser feature exposure.
* Removed `Access-Control-Allow-Origin` and CORS options entirely.
* All API endpoints now use POST to ensure proper request body handling.
* GET requests with a body are no longer allowed.
* `GetUID` endpoint now returns a proper JSON object with a `uid` field.

## Data Validation & Backend Logic

* Server-side string validation allows full UTF-8 characters; length and structural checks remain.
* Client-side is responsible for escaping HTML and rendering; official frontend guaranteed to handle this safely.
* JSON encoding/decoding still occurs server-side.
* Added `validateAndGetUID` helper to reduce code duplication (used in `handleGetUID`, `handleAddPoints`, `handleRemoveUser`).
* Added `validateAndGetPoints` helper (used in `handleAddPoints` and `handleSetPoints`).
* User UIDs and internal API key IDs now reuse the lowest available number to prevent gaps.
* Added bounds checks for UIDs and points to prevent overflows; all point operations ensure resulting sums remain within bounds.
* Rate limiter can whitelist localhost at compile time.
* Switched SQLite library to `modernc.org/sqlite` — removes CGO dependency.
* Migration functions for old keys removed.
* DB schema updated to store Argon2ID parameters with hashed keys.
* Internal API key and user ID generation now consistent and predictable.
* Fixed inconsistencies in `api.go`:

  * `handleGetAll` now uses `sendJSONResponse`.
  * `handleRemoveKey` uses `checkAuth`.
* Updated bearer token extraction to be case-insensitive and allow extra whitespace.

## Frontend / UI Updates

* Fully updated GUI admin panel; old CLI page removed.
* Home and admin pages now handle all escaping client-side to comply with CSP.
* Frontend adjusted to comply with strengthened security headers.
* API documentation updated with endpoint changes, request formats, and cURL examples.
* `serveFile` now solely responsible for vetting paths before serving files; resolves symlinks and includes a boolean option to constrain served files to the `www` directory.

## Miscellaneous Improvements

* Minor reactive fixes to logging, endpoint handling, and API compliance based on pre-release testing.
* Websites updated to comply with strengthened CSP and other security headers.

## Build & Environment Changes

* Updated `mage.go` build file with new targets:

  * `build` (default) — standard binary, defaults to current OS/Arch unless `GOOS`/`GOARCH` set.
  * `all` — builds all supported platforms.
  * `release` — builds all supported platforms and zips each with `www/` folder; requires release version string.
  * `clean` — removes `build/` folder.
* Dockerfile no longer requires CGO.
* `www/` folder now read-only.
* Resulting container ~6MB smaller.
* Removed old C version files.
* Removed `Tools` folder (documentation replaced with `APIDocs.md`).
* Removed `security.md` (misunderstood purpose).