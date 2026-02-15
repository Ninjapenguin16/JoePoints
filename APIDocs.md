# JoePoints API Documentation

Complete guide to using the JoePoints API with curl.

## Overview

The JoePoints API is a RESTful service for managing users and their point balances. All endpoints accept `POST` requests with JSON payloads and respond with JSON data.

**Key Details**:
- **Content-Type**: All requests with a body require `Content-Type: application/json`
- **Body**: All endpoints exept for getall, getidentifier, and removekey require a JSON body with the specified parameters
- **Method**: All endpoints use `POST`
- **Authentication**: Bearer token in `Authorization` header (required for write operations, optional for read-only endpoints)
- **Response Format**: JSON

---

## Authentication

API keys are required for operations that modify data (create, update, delete). Include the key in the `Authorization` header with the `Bearer` scheme:

```bash
-H "Authorization: Bearer YOUR_API_KEY"
```

**Write Operations** (requires authentication):
- `/api/genkey` - Generate new API key
- `/api/addperson` - Add user
- `/api/removeperson` - Remove user
- `/api/setpoints` - Set points
- `/api/addpoints` - Add points
- `/api/removekey` - Revoke API key
- `/api/getidentifier` - Get identifier for current key

**Read Operations** (no authentication required):
- `/api/getuid` - Lookup UID by name
- `/api/getpoints` - Get points for a user
- `/api/getall` - Get all users

---

## Endpoints

### 1. Generate API Key
**Endpoint**: `/api/genkey`  
**Authentication**: Required  

Generate a new API key with a descriptive identifier. Returns the generated key that can be used for subsequent authenticated requests.

```bash
curl -X POST /api/genkey \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer EXISTING_API_KEY" \
  -d '{"identifier":"admin-laptop"}'
```

**Response (Success - 200)**:
```json
{"key":"abcdef123456789..."}
```

**Response (Error - 403)**:
```json
{"error":"Invalid API key"}
```

**Parameters**:
- `identifier` (string, required): Label for the key (max 64 chars, printable characters only)

---

### 2. Add Person
**Endpoint**: `/api/addperson`  
**Authentication**: Required  

Create a new user with an initial point balance of zero. The system auto-generates a unique identifier (UID) for the new user.

```bash
curl -X POST /api/addperson \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"first":"John","last":"Doe"}'
```

**Response (Success - 200)**:
```json
{"uid":42}
```

**Response (Error - 409 Conflict)**:
```json
{"error":"User already exists"}
```

**Parameters**:
- `first` (string, required): First name (cannot be empty)
- `last` (string, required): Last name (cannot be empty)

---

### 3. Remove Person
**Endpoint**: `/api/removeperson`  
**Authentication**: Required  

Delete a user and all associated data by UID.

```bash
curl -X POST /api/removeperson \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"uid":42}'
```

**Response (Success - 200)**:
```json
{"status":"ok"}
```

**Parameters**:
- `uid` (integer, required): User ID to remove

---

### 4. Get UID (Lookup by Name)
**Endpoint**: `/api/getuid`  
**Authentication**: Not required  

Retrieve a user's UID by searching for them by first and last name.

```bash
curl -X POST /api/getuid \
  -H "Content-Type: application/json" \
  -d '{"first":"John","last":"Doe"}'
```

**Response (Success - 200)**:
```json
{"uid":42}
```

**Response (Error - 404)**:
```json
{"error":"No matches"}
```

**Parameters**:
- `first` (string, required): First name
- `last` (string, required): Last name

---

### 5. Get Points
**Endpoint**: `/api/getpoints`  
**Authentication**: Not required  

Retrieve the current point balance for a user by UID.

```bash
curl -X POST /api/getpoints \
  -H "Content-Type: application/json" \
  -d '{"uid":42}'
```

**Response (Success - 200)**:
```json
{"points":1500}
```

**Response (Error - 404)**:
```json
{"error":"User not found"}
```

**Parameters**:
- `uid` (integer, required): User ID

---

### 6. Set Points
**Endpoint**: `/api/setpoints`  
**Authentication**: Required  

Set a user's point balance to a specific value, replacing any existing balance.

```bash
curl -X POST /api/setpoints \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"uid":42,"points":2000}'
```

**Response (Success - 200)**:
```json
{"status":"ok"}
```

**Parameters**:
- `uid` (integer, required): User ID
- `points` (integer, required): New point value (32-bit integer range)

---

### 7. Add Points
**Endpoint**: `/api/addpoints`  
**Authentication**: Required  

Adjust a user's point balance by adding or subtracting points (use negative values to subtract).

```bash
curl -X POST /api/addpoints \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"uid":42,"points":500}'
```

**Response (Success - 200)**:
```json
{"status":"ok"}
```

**Response (Error - 400)**:
```json
{"error":"Resulting points would overflow/underflow"}
```

**Parameters**:
- `uid` (integer, required): User ID
- `points` (integer, required): Points to add (negative values subtract)

**Note**: Points are validated to prevent integer overflow/underflow

---

### 8. Get All Users
**Endpoint**: `/api/getall`  
**Authentication**: Not required  

Retrieve a complete list of all users with their UIDs, names, and current point balances.

```bash
curl -X POST /api/getall
```

**Response (Success - 200)**:
```json
[
  {"uid":1,"first":"John","last":"Doe","points":1500},
  {"uid":2,"first":"Jane","last":"Smith","points":2000}
]
```

**Parameters**: None (empty body required)

---

### 9. Get Identifier
**Endpoint**: `/api/getidentifier`  
**Authentication**: Required  

Retrieve the identifier (name/label) associated with the API key being used. Useful for verifying which key is active.

```bash
curl -X POST /api/getidentifier \
  -H "Authorization: Bearer YOUR_API_KEY" \
```

**Response (Success - 200)**:
```json
{"identifier":"admin-laptop"}
```

**Response (Error - 403)**:
```json
{"error":"Invalid API key"}
```

**Parameters**: None (empty body required)

---

### 10. Remove API Key
**Endpoint**: `/api/removekey`  
**Authentication**: Required  

Revoke an API key, causing it to become immediately invalid for all future requests. This action cannot be undone.

```bash
curl -X POST /api/removekey \
  -H "Authorization: Bearer YOUR_API_KEY" \
```

**Response (Success - 200)**:
```json
{"status":"ok"}
```

**Parameters**: None (empty body required)

**Warning**: This action is permanent and cannot be undone. The key becomes invalid immediately.

---

## Error Responses

| HTTP Status | Scenario |
|---|---|
| 200 | Success |
| 400 | Invalid input (missing fields, wrong types, values out of range) |
| 403 | Invalid or missing API key |
| 404 | Resource not found |
| 409 | Conflict (e.g., user already exists) |
| 415 | Content-Type is not application/json |
| 500 | Server error |

---

## Common Patterns

### Workflow: Create User and Set Points

```bash
# 1. Add a new user
RESPONSE=$(curl -s -X POST /api/addperson \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{"first":"Alice","last":"Johnson"}')

# Extract UID from response (requires jq)
UID=$(echo $RESPONSE | jq -r '.uid')

# 2. Set their points
curl -X POST /api/setpoints \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d "{\"uid\":$UID,\"points\":1000}"
```

### Workflow: Lookup and Add Points

```bash
# 1. Get UID by name
RESPONSE=$(curl -s -X POST /api/getuid \
  -H "Content-Type: application/json" \
  -d '{"first":"John","last":"Doe"}')

UID=$(echo $RESPONSE | jq -r '.uid')

# 2. Add points
curl -X POST /api/addpoints \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d "{\"uid\":$UID,\"points\":100}"
```

### Using jq for Pretty Output

```bash
curl -s -X POST /api/getall | jq
```

---

## API Usage Notes

**API Keys**
- Keys are provided after generation and should be stored securely
- Keep keys confidential—they grant access to write operations
- A single key can be identified using the `/api/getidentifier` endpoint
- Revoke keys when no longer needed using `/api/removekey`

**User Data**
- Each user is assigned a unique auto-incrementing identifier (UID) upon creation
- Names are trimmed of whitespace and must not be empty
- UIDs are required for point operations

**Points**
- Points are integers with a valid range (±2 billion approximately)
- Use `/api/setpoints` to replace a balance entirely
- Use `/api/addpoints` for incremental adjustments (supports negative values)
- The system validates point changes to prevent overflow/underflow errors

**General Practices**
- All requests expect `Content-Type: application/json` headers
- All responses are in JSON format
- The `/api/getall` endpoint is useful for retrieving entire datasets for reporting or display
- Error responses include descriptive messages—check the `error` field for details
- Consider caching read-only endpoint responses to reduce API calls

