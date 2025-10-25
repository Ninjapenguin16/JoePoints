#ifndef DB_H
#define DB_H

#include <sqlite3.h>
#include <stddef.h>

int db_init(const char *path);
void db_close();

// DB helpers
int db_exec(const char *sql);
int db_query(const char *sql, int (*callback)(void *, int, char **, char **),
             void *data);
sqlite3 *db_get_handle();

// User/Key helpers
/* db_create_key: create a new API key with given identifier.
 * out_key is filled with the cleartext key (hex string) and must be at least 33
 * bytes. Returns 0 on success, -1 on failure.
 */
int db_create_key(const char *identifier, char *out_key,
                  size_t len); // generates & inserts key (stored hashed)
int db_auth_key_exists(const char *key);
int db_add_user(const char *first, const char *last, int *out_uid);
int db_remove_user(int uid);
int db_get_uid_by_name(const char *first, const char *last, int **uids,
                       int *count);
int db_get_points(int uid, int *points);
int db_set_points(int uid, int points);
int db_add_points(int uid, int delta);
int db_get_all_users(char **out_json);
int db_remove_key(const char *key);

#endif
