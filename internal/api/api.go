package api

import (
	"encoding/json"
	"fmt"
	"io"
	"joepoints/internal/db"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"unicode"
)

const MaxBodySize = 16384

// getClientIPFromRequest extracts the client IP from the request
func getClientIPFromRequest(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// logAudit logs an audit event with action, API key, and details
func logAudit(action, apiKey, details string) {
	// Only show first 8 characters of key for privacy
	keyPrefix := apiKey
	if len(apiKey) > 8 {
		keyPrefix = apiKey[:8] + "..."
	}
	slog.Info("AUDIT",
		"action", action,
		"apiKey", keyPrefix,
		"details", details,
	)
}

// validateName validates first and last names
// Allows letters, digits, spaces, hyphens, and apostrophes
// Rejects control characters, HTML tags, and excessive length
func validateName(s string) bool {
	if len(s) == 0 || len(s) > 100 {
		return false
	}

	// Check for control characters and dangerous characters
	for _, c := range s {
		if c < 32 { // Allow tab, reject control chars
			return false
		}
		// Reject HTML/XML tags and dangerous characters
		if c == '<' || c == '>' || c == '"' || c == '&' || c == ';' {
			return false
		}
	}

	return true
}

// getAuthKey extracts the API key from the Authorization header
func getAuthKey(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}

	if !strings.HasPrefix(auth, "Bearer ") {
		return ""
	}

	return auth[7:]
}

// validateInput checks if a string contains only alphanumerics, _, and -
func validateInput(s string, minLen, maxLen int) bool {
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

// checkAuth validates the API key from the request
func checkAuth(r *http.Request) bool {
	key := getAuthKey(r)
	if key == "" {
		return false
	}

	if !validateInput(key, 32, 32) {
		return false
	}

	return db.DBAuthKeyExists(key)
}

// sendJSONResponse sends a JSON response with proper headers
func sendJSONResponse(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

	w.WriteHeader(statusCode)

	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// handleOptionsRequest handles CORS preflight requests
func handleOptionsRequest(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.WriteHeader(http.StatusOK)
}

// isContentTypeJSON checks if Content-Type contains application/json
func isContentTypeJSON(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "application/json")
}

// decodeJSONBody decodes JSON from request body into the provided interface
// with a size limit to prevent DoS attacks
func decodeJSONBody(r *http.Request, v interface{}) error {
	limitedReader := io.LimitReader(r.Body, int64(MaxBodySize))
	return json.NewDecoder(limitedReader).Decode(v)
}

// StringTrim removes leading and trailing whitespace
func StringTrim(s string) string {
	return strings.TrimSpace(s)
}

// --- Endpoint Handlers ---

// handleGenkey generates a new API key
func handleGenkey(w http.ResponseWriter, r *http.Request) {
	authKey := getAuthKey(r)
	if !checkAuth(r) {
		logAudit("AUTH_FAILED", "unknown", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
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
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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

	logAudit("KEY_CREATED", authKey, fmt.Sprintf("identifier=%s", identifier))
	sendJSONResponse(w, http.StatusOK, map[string]string{"key": key})
}

// handleAddperson adds a new person to the database
func handleAddperson(w http.ResponseWriter, r *http.Request) {
	authKey := getAuthKey(r)
	if !checkAuth(r) {
		logAudit("AUTH_FAILED", "unknown", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	first := StringTrim(body["first"])
	last := StringTrim(body["last"])

	if first == "" || last == "" {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or empty first or last name"})
		return
	}

	// Validate name format
	if !validateName(first) || !validateName(last) {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid name format"})
		return
	}

	uid, err := db.DBAddUser(first, last)
	if err != nil {
		sendJSONResponse(w, http.StatusConflict, map[string]string{"error": "User already exists"})
		return
	}

	logAudit("USER_ADDED", authKey, fmt.Sprintf("uid=%d, name=%s %s", uid, first, last))
	sendJSONResponse(w, http.StatusOK, map[string]interface{}{"uid": uid})
}

// handleRemoveperson removes a person from the database
func handleRemoveperson(w http.ResponseWriter, r *http.Request) {
	authKey := getAuthKey(r)
	if !checkAuth(r) {
		logAudit("AUTH_FAILED", "unknown", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON"})
		return
	}

	uidVal, ok := body["uid"]
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing uid"})
		return
	}

	uidFloat, ok := uidVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "uid must be a number"})
		return
	}

	uid := int(uidFloat)

	db.DBRemoveUser(uid)
	logAudit("USER_REMOVED", authKey, fmt.Sprintf("uid=%d", uid))
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleGetuid returns UIDs for matching first and last names
func handleGetuid(w http.ResponseWriter, r *http.Request) {
	first := StringTrim(r.URL.Query().Get("first"))
	last := StringTrim(r.URL.Query().Get("last"))

	if first == "" || last == "" {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing or empty first or last"})
		return
	}

	uids, err := db.DBGetUIDByName(first, last)
	if err != nil {
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "No matches"})
		return
	}

	sendJSONResponse(w, http.StatusOK, uids)
}

// handleGetpoints returns points for a user
func handleGetpoints(w http.ResponseWriter, r *http.Request) {
	uidStr := r.URL.Query().Get("uid")
	if uidStr == "" {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Missing uid"})
		return
	}

	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "Invalid uid"})
		return
	}

	points, err := db.DBGetPoints(uid)
	if err != nil {
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "User not found"})
		return
	}

	sendJSONResponse(w, http.StatusOK, map[string]int{"points": points})
}

// handleSetpoints sets the points for a user
func handleSetpoints(w http.ResponseWriter, r *http.Request) {
	authKey := getAuthKey(r)
	if !checkAuth(r) {
		logAudit("AUTH_FAILED", "unknown", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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

	uidFloat, ok := uidVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "uid must be a number"})
		return
	}

	pointsFloat, ok := pointsVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "points must be a number"})
		return
	}

	uid := int(uidFloat)
	points := int(pointsFloat)

	if err := db.DBSetPoints(uid, points); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to set points"})
		return
	}

	logAudit("POINTS_SET", authKey, fmt.Sprintf("uid=%d, points=%d", uid, points))
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleAddpoints adds points to a user
func handleAddpoints(w http.ResponseWriter, r *http.Request) {
	authKey := getAuthKey(r)
	if !checkAuth(r) {
		logAudit("AUTH_FAILED", "unknown", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if !isContentTypeJSON(r) {
		sendJSONResponse(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
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

	uidFloat, ok := uidVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "uid must be a number"})
		return
	}

	pointsFloat, ok := pointsVal.(float64)
	if !ok {
		sendJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "points must be a number"})
		return
	}

	uid := int(uidFloat)
	delta := int(pointsFloat)

	if err := db.DBAddPoints(uid, delta); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to add points"})
		return
	}

	logAudit("POINTS_ADDED", authKey, fmt.Sprintf("uid=%d, delta=%d", uid, delta))
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleGetall returns all users
func handleGetall(w http.ResponseWriter, r *http.Request) {
	jsonStr, err := db.DBGetAllUsers()
	if err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to retrieve users"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, jsonStr)
}

// handleRemovekey removes an API key
func handleRemovekey(w http.ResponseWriter, r *http.Request) {
	key := getAuthKey(r)
	if key == "" || !db.DBAuthKeyExists(key) {
		logAudit("AUTH_FAILED", "unknown", fmt.Sprintf("Invalid key attempt from %s", getClientIPFromRequest(r)))
		sendJSONResponse(w, http.StatusForbidden, map[string]string{"error": "Invalid API key"})
		return
	}

	if err := db.DBRemoveKey(key); err != nil {
		sendJSONResponse(w, http.StatusInternalServerError, map[string]string{"error": "Failed to remove key"})
		return
	}

	logAudit("KEY_REMOVED", key, "Key revoked by user")
	sendJSONResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// APIDispatcher routes API requests to appropriate handlers
func APIDispatcher(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Path
	method := r.Method

	if method == "OPTIONS" {
		handleOptionsRequest(w)
		return
	}

	switch {
	case url == "/api/genkey" && method == "POST":
		handleGenkey(w, r)
	case url == "/api/addperson" && method == "POST":
		handleAddperson(w, r)
	case url == "/api/removeperson" && method == "POST":
		handleRemoveperson(w, r)
	case url == "/api/setpoints" && method == "POST":
		handleSetpoints(w, r)
	case url == "/api/addpoints" && method == "POST":
		handleAddpoints(w, r)
	case url == "/api/removekey" && method == "POST":
		handleRemovekey(w, r)
	case url == "/api/getuid" && method == "GET":
		handleGetuid(w, r)
	case url == "/api/getpoints" && method == "GET":
		handleGetpoints(w, r)
	case url == "/api/getall" && method == "GET":
		handleGetall(w, r)
	default:
		sendJSONResponse(w, http.StatusNotFound, map[string]string{"error": "Unknown endpoint"})
	}
}
