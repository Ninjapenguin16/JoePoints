package api

import (
	"encoding/json"
	"fmt"
	"io"
	"joepoints/internal/db"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strings"
	"unicode"
)

const MaxBodySize = 16384

// Extracts the client IP from the request
// Note: redefined from server package to avoid circular import
func getClientIPFromRequest(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}

	return ip
}

// Sets security headers for a response writer
func SetSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

// Logs an audit event with action, API key identifier, and details
// It is expected that apiKeyIdentifier is provided from DB.DBGetKeyIdentifier
func logAudit(action, apiKeyIdentifier, details string) {
	if apiKeyIdentifier == "" {
		apiKeyIdentifier = "InvalidKey"
	}

	slog.Info("AUDIT",
		"action", action,
		"keyIdentifier", apiKeyIdentifier,
		"details", details,
	)
}

// Zeros out the bearer token in Authorization header
func zeroOutAuthKey(r *http.Request) {
	auths := r.Header["Authorization"]
	if len(auths) != 1 {
		return
	}

	parts := strings.Fields(auths[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return
	}

	// Zero out the key part
	for i := range parts[1] {
		parts[1] = parts[1][:i] + "\x00" + parts[1][i+1:]
	}

	// Reconstruct the Authorization header
	r.Header.Set("Authorization", parts[0]+" "+parts[1])
}

// Extracts the API key from the Authorization header and zeros it out in memory
func getAuthKey(r *http.Request) string {
	auths := r.Header["Authorization"]
	if len(auths) != 1 {
		return ""
	}

	parts := strings.Fields(auths[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}

	key := parts[1]

	zeroOutAuthKey(r)

	return key
}

// Checks if a string contains only base64 characters
func validateBase64(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}

	for _, c := range s {
		if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '_' && c != '-' {
			return false
		}
	}

	return true
}

// Validates the API key from the request
// Returns boolean validity and key's stored hash if valid
func checkAuth(key string) (bool, string) {
	if key == "" {
		return false, ""
	}

	if !validateBase64(key, 32, 32) {
		return false, ""
	}

	return db.DBAuthKeyExists(key)
}

// Sends a JSON response with proper headers
func sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	SetSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")

	w.WriteHeader(statusCode)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// Checks if Content-Type contains application/json
func isContentTypeJSON(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "application/json")
}

// Decodes JSON from request body into the provided interface with a size limit
func decodeJSONBody(r *http.Request, v interface{}) error {
	limitedReader := io.LimitReader(r.Body, int64(MaxBodySize))
	return json.NewDecoder(limitedReader).Decode(v)
}

// Extracts and validates a UID from an interface value
func validateAndGetUID(w http.ResponseWriter, uidVal interface{}) (int, bool) {
	uidFloat, ok := uidVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "uid must be a number"})
		return 0, false
	}

	if uidFloat != math.Trunc(uidFloat) {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "uid must be an integer"})
		return 0, false
	}

	if uidFloat < 0 || uidFloat > math.MaxInt32 {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "uid must be a non-negative 32 bit integer"})
		return 0, false
	}

	return int(uidFloat), true
}

// Extracts and validates points from an interface value
func validateAndGetPoints(w http.ResponseWriter, pointsVal interface{}) (int, bool) {
	pointsFloat, ok := pointsVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "points must be a number"})
		return 0, false
	}

	if pointsFloat != math.Trunc(pointsFloat) {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "points must be an integer"})
		return 0, false
	}

	if pointsFloat < math.MinInt32 || pointsFloat > math.MaxInt32 {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "points must be within 32 bit range"})
		return 0, false
	}

	return int(pointsFloat), true
}

// --- Endpoint Handlers ---

// Generates a new API key
func handleGenkey(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	r.ParseForm()
	if r.ContentLength == 0 {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing body"})
		return
	}

	var body map[string]string
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	identifier := body["identifier"]
	if identifier == "" {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing identifier"})
		return
	}

	if len(identifier) == 0 || len(identifier) > 64 {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid identifier length"})
		return
	}

	// Check for printable characters
	for _, c := range identifier {
		if !unicode.IsPrint(c) {
			sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid identifier characters"})
			return
		}
	}

	key, err := db.DBCreateKey(identifier)
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to create key"})
		return
	}

	// Get identifier of invoking key for logging
	authKeyIdentifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		authKeyIdentifier = ""
	}

	logAudit("KEY_CREATED", authKeyIdentifier, fmt.Sprintf("identifier=%s", identifier))
	sendJSONResponse(w, http.StatusOK, map[string]string{"key": key})
}

// Adds a new person to the database
func handleAddperson(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]string
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	first := strings.TrimSpace(body["first"])
	last := strings.TrimSpace(body["last"])

	if first == "" || last == "" {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or empty first or last name"})
		return
	}

	uid, err := db.DBAddUser(first, last)
	if err != nil {
		sendJSONResponse(w, http.StatusConflict, map[string]string{"error": "User already exists"})
		return
	}

	// Get identifier of invoking key for logging
	authKeyIdentifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		authKeyIdentifier = ""
	}

	logAudit("USER_ADDED", authKeyIdentifier, fmt.Sprintf("uid=%d, name=%s %s", uid, first, last))
	sendJSONResponse(w, http.StatusOK, map[string]interface{}{"uid": uid})
}

// Removes a person from the database
func handleRemoveperson(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	uidVal, ok := body["uid"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing uid"})
		return
	}

	uid, ok := validateAndGetUID(w, uidVal)
	if !ok {
		return
	}

	db.DBRemoveUser(uid)

	// Get identifier of invoking key for logging
	authKeyIdentifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		authKeyIdentifier = ""
	}

	logAudit("USER_REMOVED", authKeyIdentifier, fmt.Sprintf("uid=%d", uid))
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Returns UIDs for matching first and last names
func handleGetuid(w http.ResponseWriter, r *http.Request) {
	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]string
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	first := strings.TrimSpace(body["first"])
	last := strings.TrimSpace(body["last"])

	if first == "" || last == "" {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or empty first or last name"})
		return
	}

	uid, err := db.DBGetUIDByName(first, last)
	if err != nil {
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "No matches"})
		return
	}

	sendJSONResponse(w, http.StatusOK, map[string]int{"uid": uid})
	//sendJSONResponse(w, http.StatusOK, map[string]interface{}{"uid": uid})
}

// Returns the identifier for the provided API key
func handleGetIdentifier(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	identifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "API key not found"})
		return
	}

	sendJSONResponse(w, http.StatusOK, map[string]string{"identifier": identifier})
}

// Returns points for a user
func handleGetpoints(w http.ResponseWriter, r *http.Request) {
	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	uidVal, ok := body["uid"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing uid"})
		return
	}

	uid, ok := validateAndGetUID(w, uidVal)
	if !ok {
		return
	}

	points, err := db.DBGetPoints(uid)
	if err != nil {
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	sendJSONResponse(w, http.StatusOK, map[string]int{"points": points})
}

// Sets the points for a user
func handleSetpoints(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	uidVal, ok := body["uid"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing uid"})
		return
	}

	pointsVal, ok := body["points"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing points"})
		return
	}

	uid, ok := validateAndGetUID(w, uidVal)
	if !ok {
		return
	}

	points, ok := validateAndGetPoints(w, pointsVal)
	if !ok {
		return
	}

	if err := db.DBSetPoints(uid, points); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to set points"})
		return
	}

	// Get identifier of invoking key for logging
	authKeyIdentifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		authKeyIdentifier = ""
	}

	logAudit("POINTS_SET", authKeyIdentifier, fmt.Sprintf("uid=%d, points=%d", uid, points))
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Adds points to a user
func handleAddpoints(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := decodeJSONBody(r, &body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	uidVal, ok := body["uid"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing uid"})
		return
	}

	pointsVal, ok := body["points"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing points"})
		return
	}

	uid, ok := validateAndGetUID(w, uidVal)
	if !ok {
		return
	}

	points, ok := validateAndGetPoints(w, pointsVal)
	if !ok {
		return
	}

	// Ensures end sum of points is within valid range
	currentPoints, _ := db.DBGetPoints(uid)
	if (points > 0 && currentPoints > math.MaxInt32-points) || (points < 0 && currentPoints < math.MinInt32-points) {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Resulting points would overflow/underflow"})
		return
	}

	if err := db.DBAddPoints(uid, points); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to add points"})
		return
	}

	// Get identifier of invoking key for logging
	authKeyIdentifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		authKeyIdentifier = ""
	}

	logAudit("POINTS_ADDED", authKeyIdentifier, fmt.Sprintf("uid=%d, points=%d", uid, points))
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Returns all users
func handleGetall(w http.ResponseWriter, r *http.Request) {
	_ = r // Unused, kept for uniformity

	users, err := db.DBGetAllUsers()
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve users"})
		return
	}

	sendJSONResponse(w, http.StatusOK, users)
}

// Removes an API key
func handleRemovekey(w http.ResponseWriter, r *http.Request) {
	valid, authKeyHash := checkAuth(getAuthKey(r))
	if !valid {
		logAudit("AUTH_FAILED", "", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	// Get identifier of invoking key for logging before removal
	authKeyIdentifier, err := db.DBGetKeyIdentifier(authKeyHash)
	if err != nil {
		authKeyIdentifier = ""
	}

	if err := db.DBRemoveKey(authKeyHash); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to remove key"})
		return
	}

	logAudit("KEY_REMOVED", authKeyIdentifier, "Key revoked by user")
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Routes API requests to appropriate handlers
func APIDispatcher(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Path
	method := r.Method

	if method != "POST" {
		sendJSONResponse(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
		return
	}

	switch {
	case url == "/api/genkey":
		handleGenkey(w, r)
	case url == "/api/addperson":
		handleAddperson(w, r)
	case url == "/api/removeperson":
		handleRemoveperson(w, r)
	case url == "/api/setpoints":
		handleSetpoints(w, r)
	case url == "/api/addpoints":
		handleAddpoints(w, r)
	case url == "/api/removekey":
		handleRemovekey(w, r)
	case url == "/api/getuid":
		handleGetuid(w, r)
	case url == "/api/getpoints":
		handleGetpoints(w, r)
	case url == "/api/getall":
		handleGetall(w, r)
	case url == "/api/getidentifier":
		handleGetIdentifier(w, r)
	default:
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "Unknown endpoint"})
	}
}
