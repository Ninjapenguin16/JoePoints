#ifndef API_H
#define API_H

#include <microhttpd.h>
#include <stddef.h> // for size_t

/* Maximum allowed request body size (bytes) for JSON POSTs */
#define API_MAX_BODY_SIZE 16384

// Per-connection POST data
struct connection_info_struct {
  char *post_data;
  struct MHD_PostProcessor *post_processor;
};

// Forward declarations of endpoint handlers
enum MHD_Result handle_api_request(struct MHD_Connection *conn, const char *url,
                                   const char *method, const char *upload_data,
                                   size_t *upload_data_size,
                                   struct connection_info_struct *con_info);

enum MHD_Result handle_genkey(struct MHD_Connection *conn,
                              const char *post_data);
enum MHD_Result handle_addperson(struct MHD_Connection *conn,
                                 const char *post_data);
enum MHD_Result handle_removeperson(struct MHD_Connection *conn,
                                    const char *post_data);
enum MHD_Result handle_getuid(struct MHD_Connection *conn);
enum MHD_Result handle_getpoints(struct MHD_Connection *conn);
enum MHD_Result handle_setpoints(struct MHD_Connection *conn,
                                 const char *post_data);
enum MHD_Result handle_addpoints(struct MHD_Connection *conn,
                                 const char *post_data);
enum MHD_Result handle_getall(struct MHD_Connection *conn);
enum MHD_Result handle_removekey(struct MHD_Connection *conn);

// Callback for POST data accumulation
enum MHD_Result iterate_post(void *coninfo_cls, enum MHD_ValueKind kind,
                             const char *key, const char *filename,
                             const char *content_type,
                             const char *transfer_encoding, const char *data,
                             uint64_t off, size_t size);

// Helper to send JSON response
void send_json_response(struct MHD_Connection *conn, int status_code,
                        const char *json);

#endif // API_H
