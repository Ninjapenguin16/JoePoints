#include "api.h"

#include "db.h"

#include <ctype.h>
#include <json-c/json.h>
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define MAX_KEY_LEN 33
// Use shared limit from header
#ifndef API_MAX_BODY_SIZE
#define API_MAX_BODY_SIZE 16384
#endif

// --- Helpers ---

// Check if string is alphanumerics with the exception of _ and -
int validate_input(const char* s, size_t min, size_t max) {
    if(!s) {
        return 0;
    }

    size_t len = strlen(s);
    if(len < min || len > max) {
        return 0;
    }

    char c;
    for(size_t i = 0; i < len; i++) {
        c = (unsigned char)s[i];
        if(!isalnum(c) && c != '_' && c != '-') {
            return 0;
        }
    }

    return 1;
}

void send_json_response(struct MHD_Connection* conn, int status, const char* json_str) {
    struct MHD_Response* resp = MHD_create_response_from_buffer(strlen(json_str), (void*)json_str, MHD_RESPMEM_MUST_COPY);

    // Standard headers
    MHD_add_response_header(resp, "Content-Type", "application/json");

    // CORS headers
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Authorization, Content-Type");

    MHD_queue_response(conn, status, resp);
    MHD_destroy_response(resp);
}

/* forward declaration */
static int is_content_type_json(struct MHD_Connection* conn);

enum MHD_Result handle_options_request(struct MHD_Connection* conn) {
    struct MHD_Response* resp =
        MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);

    // CORS headers
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_add_response_header(resp, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(resp, "Access-Control-Allow-Headers", "Authorization, Content-Type");

    // Return 200 OK with empty body
    MHD_queue_response(conn, MHD_HTTP_OK, resp);
    MHD_destroy_response(resp);

    return MHD_YES;
}

char* get_auth_key(struct MHD_Connection* conn) {
    const char* auth = MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Authorization");

    if(!auth || strncmp(auth, "Bearer ", 7) != 0) {
        return NULL;
    }

    return (char*)(auth + 7);
}

int check_auth(struct MHD_Connection* conn) {
    printf("[API] check_auth called\n");
    fflush(stdout);
    char* key = get_auth_key(conn);
    printf("[API] extracted key ptr=%p key='%s'\n", (void*)key, key ? key : "(null)");
    fflush(stdout);
    if(!key) {
        return 0;
    }

    if(!validate_input(key, 32, 32)) {
        printf("[API] Invalid API key");
        fflush(stdout);
        return 0;
    }

    int tmp = db_auth_key_exists(key);
    printf("[API] db_auth_key_exists returned %d for key '%s'\n", tmp, key);
    fflush(stdout);

    return tmp;
}

struct json_object* parse_json(const char* data) {
    if(!data || !*data) {
        return NULL;
    }

    return json_tokener_parse(data);
}

static char* str_trim(char* str) {
    if(!str) {
        return NULL;
    }

    // Trim leading whitespace
    while(*str && isspace((unsigned char)*str)) {
        str++;
    }

    // Trim trailing whitespace
    char* end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) {
        *end-- = '\0';
    }

    return str;
}

// --- POST data accumulator ---

enum MHD_Result iterate_post(void* coninfo_cls, enum MHD_ValueKind kind, const char* key, const char* filename, const char* content_type, const char* transfer_encoding, const char* data, uint64_t off, size_t size) {
    struct connection_info_struct* con_info = coninfo_cls;
    printf("[API] iterate_post called: con_info=%p off=%" PRIu64 " size=%zu key=%s\n", (void*)con_info, off, size, key ? key : "(null)");
    fflush(stdout);

    if(size > 0) {
        size_t old_len = con_info->post_data ? strlen(con_info->post_data) : 0;
        if(old_len + size > API_MAX_BODY_SIZE) {
            /* Body too large */
            fprintf(stderr, "[API] iterate_post: body too large (%zu bytes)\n", old_len + size);

            return MHD_NO;
        }
        char* new_buf = realloc(con_info->post_data, old_len + size + 1);
        if(!new_buf) {
            fprintf(stderr, "[API] iterate_post: realloc failed\n");

            return MHD_NO;
        }
        con_info->post_data = new_buf;
        if(off == 0) {
            con_info->post_data[0] = '\0';
        }
        memcpy(con_info->post_data + old_len, data, size);
        con_info->post_data[old_len + size] = '\0';
    }

    return MHD_YES;
}

// --- Endpoint Implementations ---

enum MHD_Result handle_genkey(struct MHD_Connection* conn, const char* body) {
    if(!check_auth(conn)) {
        send_json_response(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Invalid API key\"}");

        return MHD_YES;
    }

    if(!is_content_type_json(conn)) {
        send_json_response(conn, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, "{\"error\":\"Content-Type must be application/json\"}");

        return MHD_YES;
    }

    if(!body || strlen(body) == 0) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing body (identifier required)\"}");

        return MHD_YES;
    }

    char* copy = strdup(body);
    struct json_object* json = parse_json(copy);
    free(copy);
    if(!json) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");

        return MHD_YES;
    }

    struct json_object* tmp;
    const char* identifier = NULL;
    if(json_object_object_get_ex(json, "identifier", &tmp)) {
        identifier = json_object_get_string(tmp);
    }
    if(!identifier) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing identifier\"}");
        json_object_put(json);

        return MHD_YES;
    }

    // Validate identifier length and characters
    if(strlen(identifier) == 0 || strlen(identifier) > 64) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid identifier length\"}");
        json_object_put(json);

        return MHD_YES;
    }
    for(size_t i = 0; i < strlen(identifier); ++i) {
        if(!isprint((unsigned char)identifier[i])) {
            send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid identifier characters\"}");
            json_object_put(json);

            return MHD_YES;
        }
    }

    char key[MAX_KEY_LEN];
    if(db_create_key(identifier, key, sizeof(key)) != 0) {
        send_json_response(conn, MHD_HTTP_INTERNAL_SERVER_ERROR, "{\"error\":\"Failed to create key\"}");
        json_object_put(json);

        return MHD_YES;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "{\"key\":\"%s\"}", key);
    send_json_response(conn, MHD_HTTP_OK, buf);

    json_object_put(json);

    return MHD_YES;
}

/* Helper: check Content-Type contains application/json (case-insensitive) */
static int is_content_type_json(struct MHD_Connection* conn) {
    const char* ct =
        MHD_lookup_connection_value(conn, MHD_HEADER_KIND, "Content-Type");
    if(!ct) {
        return 0;
    }
    /* simple case-insensitive check */
    const char* p = strcasestr(ct, "application/json");

    return p != NULL;
}

enum MHD_Result handle_addperson(struct MHD_Connection* conn, const char* body) {
    printf("[API] handle_addperson ran\n");
    if(!check_auth(conn)) {
        send_json_response(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Invalid API key\"}");

        return MHD_YES;
    }
    if(!is_content_type_json(conn)) {
        send_json_response(conn, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, "{\"error\":\"Content-Type must be application/json\"}");

        return MHD_YES;
    }

    if(!body || strlen(body) == 0) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Empty body\"}");

        return MHD_YES;
    }
    char* copy = strdup(body);
    struct json_object* json = parse_json(copy);
    free(copy);
    if(!json) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");

        return MHD_YES;
    }

    const char *first = NULL, *last = NULL;
    struct json_object* tmp;
    if(json_object_object_get_ex(json, "first", &tmp)) {
        first = json_object_get_string(tmp);
    }
    if(json_object_object_get_ex(json, "last", &tmp)) {
        last = json_object_get_string(tmp);
    }

    // Trim whitespace
    char* first_trimmed = first ? str_trim(strdup(first)) : NULL;
    char* last_trimmed = last ? str_trim(strdup(last)) : NULL;

    if(!first_trimmed || !last_trimmed || strlen(first_trimmed) == 0 || strlen(last_trimmed) == 0) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing or empty first or last name\"}");
        free(first_trimmed);
        free(last_trimmed);
        json_object_put(json);

        return MHD_YES;
    }

    int uid = 0;
    if(db_add_user(first_trimmed, last_trimmed, &uid) != 0) {
        send_json_response(conn, MHD_HTTP_CONFLICT, "{\"error\":\"User already exists\"}");
        free(first_trimmed);
        free(last_trimmed);
        json_object_put(json);

        return MHD_YES;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "{\"uid\":%d}", uid);
    send_json_response(conn, MHD_HTTP_OK, buf);

    free(first_trimmed);
    free(last_trimmed);
    json_object_put(json);

    return MHD_YES;
}

enum MHD_Result handle_removeperson(struct MHD_Connection* conn, const char* body) {
    if(!check_auth(conn)) {
        send_json_response(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Invalid API key\"}");

        return MHD_YES;
    }

    if(!is_content_type_json(conn)) {
        send_json_response(conn, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, "{\"error\":\"Content-Type must be application/json\"}");

        return MHD_YES;
    }

    char* copy = strdup(body);
    struct json_object* json = parse_json(copy);
    free(copy);
    if(!json) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");

        return MHD_YES;
    }

    struct json_object* tmp;
    if(!json_object_object_get_ex(json, "uid", &tmp)) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing uid\"}");
        json_object_put(json);

        return MHD_YES;
    }



    errno = 0;
    int uid = json_object_get_int(tmp);
    if(errno == EINVAL) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid number format\"}");
        json_object_put(json);
        return MHD_YES;
    }

    db_remove_user(uid);
    send_json_response(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    json_object_put(json);

    return MHD_YES;
}

enum MHD_Result handle_getuid(struct MHD_Connection* conn) {
    const char* first =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "first");
    const char* last =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "last");

    // Trim whitespace
    char* first_trimmed = first ? str_trim(strdup(first)) : NULL;
    char* last_trimmed = last ? str_trim(strdup(last)) : NULL;

    if(!first_trimmed || !last_trimmed || strlen(first_trimmed) == 0 || strlen(last_trimmed) == 0) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing or empty first or last\"}");
        free(first_trimmed);
        free(last_trimmed);

        return MHD_YES;
    }

    int* uids = NULL;
    int count = 0;
    if(db_get_uid_by_name(first_trimmed, last_trimmed, &uids, &count) != 0) {
        send_json_response(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"No matches\"}");
        free(first_trimmed);
        free(last_trimmed);

        return MHD_YES;
    }

    struct json_object* arr = json_object_new_array();
    for(int i = 0; i < count; i++) {
        json_object_array_add(arr, json_object_new_int(uids[i]));
    }
    const char* out = json_object_to_json_string(arr);
    send_json_response(conn, MHD_HTTP_OK, out);

    free(uids);
    json_object_put(arr);
    free(first_trimmed);
    free(last_trimmed);

    return MHD_YES;
}

enum MHD_Result handle_getpoints(struct MHD_Connection* conn) {
    const char* uid_str =
        MHD_lookup_connection_value(conn, MHD_GET_ARGUMENT_KIND, "uid");
    if(!uid_str) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing uid\"}");

        return MHD_YES;
    }

    int uid = atoi(uid_str);
    int points = 0;
    if(db_get_points(uid, &points) != 0) {
        send_json_response(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"User not found\"}");

        return MHD_YES;
    }

    char buf[64];
    snprintf(buf, sizeof(buf), "{\"points\":%d}", points);
    send_json_response(conn, MHD_HTTP_OK, buf);

    return MHD_YES;
}

enum MHD_Result handle_setpoints(struct MHD_Connection* conn, const char* body) {
    if(!check_auth(conn)) {
        send_json_response(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Invalid API key\"}");

        return MHD_YES;
    }

    if(!is_content_type_json(conn)) {
        send_json_response(conn, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, "{\"error\":\"Content-Type must be application/json\"}");

        return MHD_YES;
    }

    char* copy = strdup(body);
    struct json_object* json = parse_json(copy);
    free(copy);
    if(!json) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");

        return MHD_YES;
    }

    struct json_object* tmp;
    int uid = 0, points = 0;

    if(!json_object_object_get_ex(json, "uid", &tmp)) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing uid\"}");
        json_object_put(json);

        return MHD_YES;
    }
    errno = 0;
    uid = json_object_get_int(tmp);
    if(errno == EINVAL) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid number format\"}");
        json_object_put(json);
        return MHD_YES;
    }

    if(!json_object_object_get_ex(json, "points", &tmp)) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing points\"}");
        json_object_put(json);

        return MHD_YES;
    }
    errno = 0;
    points = json_object_get_int(tmp);
    if(errno == EINVAL) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid number format\"}");
        json_object_put(json);
        return MHD_YES;
    }

    db_set_points(uid, points);
    send_json_response(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    json_object_put(json);

    return MHD_YES;
}

enum MHD_Result handle_addpoints(struct MHD_Connection* conn, const char* body) {
    if(!check_auth(conn)) {
        send_json_response(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Invalid API key\"}");

        return MHD_YES;
    }

    if(!is_content_type_json(conn)) {
        send_json_response(conn, MHD_HTTP_UNSUPPORTED_MEDIA_TYPE, "{\"error\":\"Content-Type must be application/json\"}");

        return MHD_YES;
    }

    char* copy = strdup(body);
    struct json_object* json = parse_json(copy);
    free(copy);
    if(!json) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid JSON\"}");

        return MHD_YES;
    }

    struct json_object* tmp;
    int uid = 0, delta = 0;

    if(!json_object_object_get_ex(json, "uid", &tmp)) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing uid\"}");
        json_object_put(json);

        return MHD_YES;
    }
    errno = 0;
    uid = json_object_get_int(tmp);
    if (errno == EINVAL) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid number format\"}");
        json_object_put(json);
        return MHD_YES;
    }

    if(!json_object_object_get_ex(json, "points", &tmp)) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Missing points\"}");
        json_object_put(json);

        return MHD_YES;
    }
    errno = 0;
    delta = json_object_get_int(tmp);
    if (errno == EINVAL) {
        send_json_response(conn, MHD_HTTP_BAD_REQUEST, "{\"error\":\"Invalid number format\"}");
        json_object_put(json);
        return MHD_YES;
    }

    db_add_points(uid, delta);
    send_json_response(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");
    json_object_put(json);

    return MHD_YES;
}

enum MHD_Result handle_getall(struct MHD_Connection* conn) {
    char* json = NULL;
    db_get_all_users(&json);
    send_json_response(conn, MHD_HTTP_OK, json);
    free(json);

    return MHD_YES;
}

enum MHD_Result handle_removekey(struct MHD_Connection* conn) {
    char* key = get_auth_key(conn);
    if(!key || !db_auth_key_exists(key)) {
        send_json_response(conn, MHD_HTTP_FORBIDDEN, "{\"error\":\"Invalid API key\"}");

        return MHD_YES;
    }
    db_remove_key(key);
    send_json_response(conn, MHD_HTTP_OK, "{\"status\":\"ok\"}");

    return MHD_YES;
}

// --- Dispatcher ---
enum MHD_Result handle_api_request(struct MHD_Connection* conn, const char* url, const char* method, const char* upload_data, size_t* upload_data_size, struct connection_info_struct* con_info) {
    // at top of handle_api_request
    printf("[API] handle_api_request entry: url='%s' method='%s' con_info=%p "
           "upload_data=%p upload_data_size=%p\n",
           url ? url : "(null)", method ? method : "(null)", (void*)con_info, (void*)upload_data, (void*)upload_data_size);
    fflush(stdout);
    if(con_info) {
        printf("[API] con_info->post_data exists? %s len=%zu\n", con_info->post_data ? "yes" : "no", con_info->post_data ? strlen(con_info->post_data) : 0);
        fflush(stdout);
    }

    // If POST request with unprocessed data, wait for full POST
    if(con_info && *upload_data_size > 0) {
        MHD_post_process(con_info->post_processor, upload_data, *upload_data_size);
        *upload_data_size = 0;

        return MHD_YES;
    }

    if(strcmp(method, "OPTIONS") == 0) {
        return handle_options_request(conn);
    }

    if(strcmp(url, "/api/genkey") == 0 && strcmp(method, "POST") == 0) {
        return handle_genkey(conn, con_info ? con_info->post_data : NULL);
    }

    if(strcmp(url, "/api/addperson") == 0 && strcmp(method, "POST") == 0) {
        return handle_addperson(conn, con_info ? con_info->post_data : NULL);
    }

    if(strcmp(url, "/api/removeperson") == 0 && strcmp(method, "POST") == 0) {
        return handle_removeperson(conn, con_info ? con_info->post_data : NULL);
    }

    if(strcmp(url, "/api/setpoints") == 0 && strcmp(method, "POST") == 0) {
        return handle_setpoints(conn, con_info ? con_info->post_data : NULL);
    }

    if(strcmp(url, "/api/addpoints") == 0 && strcmp(method, "POST") == 0) {
        return handle_addpoints(conn, con_info ? con_info->post_data : NULL);
    }

    if(strcmp(url, "/api/removekey") == 0 && strcmp(method, "POST") == 0) {
        return handle_removekey(conn);
    }

    if(strcmp(url, "/api/getuid") == 0 && strcmp(method, "GET") == 0) {
        return handle_getuid(conn);
    }

    if(strcmp(url, "/api/getpoints") == 0 && strcmp(method, "GET") == 0) {
        return handle_getpoints(conn);
    }

    if(strcmp(url, "/api/getall") == 0 && strcmp(method, "GET") == 0) {
        return handle_getall(conn);
    }

    send_json_response(conn, MHD_HTTP_NOT_FOUND, "{\"error\":\"Unknown endpoint\"}");

    return MHD_YES;
}

// a8a3414994dbc167759142ba4eaa6ee5
