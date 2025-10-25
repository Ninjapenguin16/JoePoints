#include "api.h"

#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct MHD_Daemon *http_daemon = NULL;

// Forward declaration
static enum MHD_Result
request_handler(void *cls, struct MHD_Connection *connection, const char *url,
                const char *method, const char *version,
                const char *upload_data, size_t *upload_data_size,
                void **con_cls);

static enum MHD_Result serve_file(struct MHD_Connection *conn,
                                  const char *filepath) {
  FILE *f = fopen(filepath, "rb");
  if (!f) {

    return MHD_NO;
  }

  // Get file size
  struct stat st;
  if (stat(filepath, &st) != 0) {
    fclose(f);

    return MHD_NO;
  }
  size_t filesize = st.st_size;

  char *buffer = malloc(filesize);
  if (!buffer) {
    fclose(f);

    return MHD_NO;
  }
  size_t nread = fread(buffer, 1, filesize, f);
  if (nread != filesize) {
    fprintf(stderr, "[SRV] Warning: fread read %zu of %zu bytes\n", nread,
            filesize);
  }
  fclose(f);

  // Determine MIME type by extension
  const char *mime = "application/octet-stream";
  const char *ext = strrchr(filepath, '.');
  if (ext) {
    if (strcmp(ext, ".html") == 0) {
      mime = "text/html";
    } else if (strcmp(ext, ".css") == 0) {
      mime = "text/css";
    } else if (strcmp(ext, ".js") == 0) {
      mime = "application/javascript";
    }
  }

  struct MHD_Response *resp =
      MHD_create_response_from_buffer(filesize, buffer, MHD_RESPMEM_MUST_FREE);
  MHD_add_response_header(resp, "Content-Type", mime);
  MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*"); // CORS
  MHD_queue_response(conn, MHD_HTTP_OK, resp);
  MHD_destroy_response(resp);

  return MHD_YES;
}

// Start server on given port
int start_server(unsigned int port) {
  http_daemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
                                 &request_handler, NULL, MHD_OPTION_END);

  if (!http_daemon) {
    fprintf(stderr, "Failed to start server\n");

    return 1;
  }

  printf("Server listening on port %u\n", port);

  return 0;
}

// Stop the server
void stop_server(void) {
  if (http_daemon) {
    MHD_stop_daemon(http_daemon);
    http_daemon = NULL;
  }
}

// Request handler
static enum MHD_Result
request_handler(void *cls, struct MHD_Connection *connection, const char *url,
                const char *method, const char *version,
                const char *upload_data, size_t *upload_data_size,
                void **con_cls) {
  struct connection_info_struct *con_info = *con_cls;

  // First call: create per-connection struct
  if (con_info == NULL) {
    con_info = calloc(1, sizeof(*con_info));
    if (!con_info) {

      return MHD_NO;
    }

    con_info->post_data = NULL;
    con_info->post_processor = NULL;

    *con_cls = con_info;

    return MHD_YES; // wait for POST data
  }

  // If POST and data present, accumulate
  if (method && strcmp(method, "POST") == 0 && upload_data_size &&
      *upload_data_size > 0) {
    size_t old_len = con_info->post_data ? strlen(con_info->post_data) : 0;
    /* Enforce maximum POST body size to avoid unbounded allocations */
    if (old_len + *upload_data_size > API_MAX_BODY_SIZE) {
      /* Do not accept more data */
      fprintf(stderr, "[SRV] request body too large: %zu bytes\n",
              old_len + *upload_data_size);

      return MHD_NO;
    }
    con_info->post_data =
        realloc(con_info->post_data, old_len + *upload_data_size + 1);
    if (!con_info->post_data) {

      return MHD_NO;
    }

    memcpy(con_info->post_data + old_len, upload_data, *upload_data_size);
    con_info->post_data[old_len + *upload_data_size] = '\0';

    *upload_data_size = 0;

    return MHD_YES;
  }

  // Serve static files if URL does not start with /api/
  if (strncmp(url, "/api/", 5) != 0) {
    char filepath[512];

    if (strcmp(url, "/") == 0) {
      snprintf(filepath, sizeof(filepath), "www/index.html");
    } else if (strcmp(url, "/cli") == 0) {
      snprintf(filepath, sizeof(filepath),
               "www/cli.html"); // redirect /cli to cli.html
    } else {
      snprintf(filepath, sizeof(filepath), "www%s", url);
    }

    struct stat st;
    if (stat(filepath, &st) == 0 && S_ISREG(st.st_mode)) {

      return serve_file(connection, filepath);
    }

    // If file not found, return 404
    struct MHD_Response *resp = MHD_create_response_from_buffer(
        strlen("404 Not Found"), (void *)"404 Not Found",
        MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(resp, "Content-Type", "text/plain");
    MHD_add_response_header(resp, "Access-Control-Allow-Origin", "*");
    MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
    MHD_destroy_response(resp);

    return MHD_YES;
  }

  // Handle API request
  /* Optionally check content-type early for large POSTs; handlers perform
  stricter checks. We rely mainly on api.c handlers for content-type
  semantics. */
  enum MHD_Result ret = handle_api_request(
      connection, url, method, con_info->post_data, upload_data_size, con_info);

  // Cleanup per-connection memory
  if (con_info->post_data) {
    free(con_info->post_data);
  }
  free(con_info);
  *con_cls = NULL;

  return ret;
}
