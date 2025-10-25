#include "db.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static sqlite3 *db = NULL;

// Utility: generate 32-char hex key
static void generate_random_key(char *key, size_t len) {
  if (!key || len < 33)

    return;
  unsigned char buf[16];
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "Failed to open /dev/urandom: %s\n", strerror(errno));

    return;
  }
  ssize_t r = read(fd, buf, sizeof(buf));
  if (r != (ssize_t)sizeof(buf)) {
    fprintf(stderr, "Failed to read random bytes: %zd\n", r);
    close(fd);

    return;
  }
  close(fd);
  for (int i = 0; i < 16; ++i) {
    sprintf(key + i * 2, "%02x", buf[i]);
  }
  key[32] = '\0';
}

#include "crypto.h"

int db_init(const char *path) {
  /* Ensure SQLite is in serialized mode for thread-safety. Must be called
   * before sqlite3_open_v2 */
  if (sqlite3_config(SQLITE_CONFIG_SERIALIZED) != SQLITE_OK) {
    fprintf(stderr,
            "Warning: sqlite3_config(SQLITE_CONFIG_SERIALIZED) failed\n");
    /* continue, attempt to open DB anyway */
  }

  if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                      NULL) != SQLITE_OK) {
    fprintf(stderr, "Failed to open DB: %s\n",
            db ? sqlite3_errmsg(db) : "(null)");
    if (db)
      sqlite3_close(db);
    db = NULL;

    return -1;
  }

  // Ensure users table exists
  db_exec("CREATE TABLE IF NOT EXISTS users (uid INTEGER PRIMARY KEY, first "
          "TEXT, last TEXT, points INTEGER DEFAULT 0);");

  // Handle keys table schema and migration from legacy schema (keys.key)
  int keys_exists = 0;
  sqlite3_stmt *chk = NULL;
  if (sqlite3_prepare_v2(
          db,
          "SELECT name FROM sqlite_master WHERE type='table' AND name='keys';",
          -1, &chk, NULL) == SQLITE_OK) {
    if (sqlite3_step(chk) == SQLITE_ROW)
      keys_exists = 1;
  }
  if (chk)
    sqlite3_finalize(chk);

  if (!keys_exists) {
    db_exec("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, "
            "identifier TEXT, key_hash TEXT, salt TEXT);");
  } else {
    // Inspect columns to see if we need to migrate
    int has_plain = 0, has_hash = 0;
    sqlite3_stmt *colstmt = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(keys);", -1, &colstmt,
                           NULL) == SQLITE_OK) {
      while (sqlite3_step(colstmt) == SQLITE_ROW) {
        const unsigned char *colname = sqlite3_column_text(colstmt, 1);
        if (!colname)
          continue;
        if (strcmp((const char *)colname, "key") == 0)
          has_plain = 1;
        if (strcmp((const char *)colname, "key_hash") == 0)
          has_hash = 1;
      }
    }
    if (colstmt)
      sqlite3_finalize(colstmt);

    if (!has_hash) {
      if (has_plain) {
        // Legacy table with plaintext keys: migrate to new schema
        db_exec("BEGIN TRANSACTION;");
        db_exec("CREATE TABLE IF NOT EXISTS keys_new (id INTEGER PRIMARY KEY, "
                "identifier TEXT, key_hash TEXT, salt TEXT);");
        sqlite3_stmt *rstmt = NULL;
        if (sqlite3_prepare_v2(db, "SELECT key FROM keys;", -1, &rstmt, NULL) ==
            SQLITE_OK) {
          while (sqlite3_step(rstmt) == SQLITE_ROW) {
            const unsigned char *oldkey = sqlite3_column_text(rstmt, 0);
            if (!oldkey)
              continue;
            // Hash and insert
            uint8_t salt_raw[16];
            if (generate_salt_bytes(salt_raw, sizeof(salt_raw)) != 0)
              continue;
            char salt_hex[33];
            hex_encode(salt_raw, sizeof(salt_raw), salt_hex, sizeof(salt_hex));
            uint8_t dk[32];
            if (pbkdf2_hmac_sha256(oldkey, strlen((const char *)oldkey),
                                   salt_raw, sizeof(salt_raw), 100000, dk,
                                   sizeof(dk)) != 0)
              continue;
            char hash_hex[65];
            hex_encode(dk, sizeof(dk), hash_hex, sizeof(hash_hex));

            sqlite3_stmt *inst = NULL;
            if (sqlite3_prepare_v2(db,
                                   "INSERT INTO keys_new (identifier, "
                                   "key_hash, salt) VALUES (?, ?, ?);",
                                   -1, &inst, NULL) == SQLITE_OK) {
              sqlite3_bind_text(inst, 1, "FirstRun", -1, SQLITE_TRANSIENT);
              sqlite3_bind_text(inst, 2, hash_hex, -1, SQLITE_TRANSIENT);
              sqlite3_bind_text(inst, 3, salt_hex, -1, SQLITE_TRANSIENT);
              sqlite3_step(inst);
              sqlite3_finalize(inst);
            }
          }
          sqlite3_finalize(rstmt);
        }
        db_exec("DROP TABLE keys;");
        db_exec("ALTER TABLE keys_new RENAME TO keys;");
        db_exec("COMMIT;");
      } else {
        // No key_hash column and no legacy key column; recreate table with new
        // schema
        db_exec("DROP TABLE IF EXISTS keys;");
        db_exec("CREATE TABLE IF NOT EXISTS keys (id INTEGER PRIMARY KEY, "
                "identifier TEXT, key_hash TEXT, salt TEXT);");
      }
    }
  }

  // If no keys exist, generate one and print
  int count = 0;
  sqlite3_stmt *stmt;
  sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM keys;", -1, &stmt, NULL);
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    count = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);

  if (count == 0) {
    char key[33];
    if (db_create_key("FirstRun", key, sizeof(key)) == 0) {
      printf("Initial API Key: %s\n", key);
    } else {
      fprintf(stderr, "Failed to create initial API key\n");
    }
  }

  return 0;
}

void db_close() {
  if (db) {
    sqlite3_close(db);
  }
}

// Generic exec/query helpers
int db_exec(const char *sql) {
  if (!db)

    return -1;
  char *err = NULL;
  if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
    fprintf(stderr, "SQL error: %s\n", err ? err : "(null)");
    if (err)
      sqlite3_free(err);

    return -1;
  }

  return 0;
}

int db_query(const char *sql, int (*callback)(void *, int, char **, char **),
             void *data) {
  if (!db)

    return -1;
  char *err = NULL;
  if (sqlite3_exec(db, sql, callback, data, &err) != SQLITE_OK) {
    fprintf(stderr, "SQL query error: %s\n", err ? err : "(null)");
    if (err)
      sqlite3_free(err);

    return -1;
  }

  return 0;
}

sqlite3 *db_get_handle() { return db; }

int db_create_key(const char *identifier, char *out_key, size_t len) {
  if (!identifier || !out_key || len < 33)

    return -1;
  if (!db)

    return -1;

  // Generate cleartext key
  generate_random_key(out_key, len);

  // Generate salt bytes
  const size_t salt_bytes = 16;
  uint8_t salt_raw[16];
  if (generate_salt_bytes(salt_raw, salt_bytes) != 0)

    return -1;

  // Derive key hash with PBKDF2-HMAC-SHA256
  const uint32_t iterations = 100000;
  uint8_t dk[32];
  if (pbkdf2_hmac_sha256((const uint8_t *)out_key, strlen(out_key), salt_raw,
                         salt_bytes, iterations, dk, sizeof(dk)) != 0)

    return -1;

  char hash_hex[65];
  char salt_hex[33];
  hex_encode(dk, sizeof(dk), hash_hex, sizeof(hash_hex));
  hex_encode(salt_raw, salt_bytes, salt_hex, sizeof(salt_hex));

  // Insert into DB
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(
      db, "INSERT INTO keys (identifier, key_hash, salt) VALUES (?,?,?);", -1,
      &stmt, NULL);
  if (rc != SQLITE_OK) {
    fprintf(stderr, "db_create_key: prepare failed: %s\n", sqlite3_errmsg(db));
    if (stmt)
      sqlite3_finalize(stmt);

    return -1;
  }
  sqlite3_bind_text(stmt, 1, identifier, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, hash_hex, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, salt_hex, -1, SQLITE_TRANSIENT);

  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    fprintf(stderr, "db_create_key: step failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);

    return -1;
  }
  sqlite3_finalize(stmt);

  return 0;
}

int db_auth_key_exists(const char *key) {
  if (!db || !key)

    return 0;
  sqlite3_stmt *stmt = NULL;
  int found = 0;
  int rc = sqlite3_prepare_v2(db, "SELECT key_hash, salt FROM keys;", -1, &stmt,
                              NULL);
  if (rc != SQLITE_OK)

    return 0;
  const uint32_t iterations = 100000;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const unsigned char *kh = sqlite3_column_text(stmt, 0);
    const unsigned char *salt_hex = sqlite3_column_text(stmt, 1);
    if (!kh || !salt_hex)
      continue;
    size_t salt_hex_len = strlen((const char *)salt_hex);
    size_t salt_bytes = salt_hex_len / 2;
    uint8_t salt_raw[64];
    if (salt_bytes > sizeof(salt_raw))
      continue;
    if (hex_decode((const char *)salt_hex, salt_raw, salt_bytes) != 0)
      continue;

    uint8_t dk[32];
    if (pbkdf2_hmac_sha256((const uint8_t *)key, strlen(key), salt_raw,
                           salt_bytes, iterations, dk, sizeof(dk)) != 0)
      continue;
    char dk_hex[65];
    hex_encode(dk, sizeof(dk), dk_hex, sizeof(dk_hex));
    if (strcmp(dk_hex, (const char *)kh) == 0) {
      found = 1;
      break;
    }
  }
  sqlite3_finalize(stmt);

  return found;
}

int db_add_user(const char *first, const char *last, int *out_uid) {
  sqlite3_stmt *stmt;
  int rc;

  // Check duplicate
  if (!db)

    return -1;
  rc = sqlite3_prepare_v2(
      db, "SELECT COUNT(*) FROM users WHERE first=? AND last=?;", -1, &stmt,
      NULL);
  if (rc != SQLITE_OK) {
    printf("[db] prepare failed: %s\n", sqlite3_errmsg(db));

    return -1;
  }
  sqlite3_bind_text(stmt, 1, first, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, last, -1, SQLITE_TRANSIENT);
  int duplicate = 0;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    duplicate = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  if (duplicate > 0) {

    return -1;
  }

  // Determine UID
  int uid = 1; // default for empty table
  rc = sqlite3_prepare_v2(db,
                          "SELECT MIN(t1.uid + 1) "
                          "FROM users t1 "
                          "LEFT JOIN users t2 ON t1.uid + 1 = t2.uid "
                          "WHERE t2.uid IS NULL;",
                          -1, &stmt, NULL);
  if (rc != SQLITE_OK) {
    printf("[db] prepare failed: %s\n", sqlite3_errmsg(db));

    return -1;
  }
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    int candidate = sqlite3_column_int(stmt, 0);
    if (candidate > 0) {
      uid = candidate; // use found UID if table not empty
    }
  }
  sqlite3_finalize(stmt);

  // Insert new user with the chosen UID
  rc = sqlite3_prepare_v2(
      db, "INSERT INTO users (uid, first, last, points) VALUES (?,?,?,0);", -1,
      &stmt, NULL);
  if (rc != SQLITE_OK) {
    printf("[db] prepare failed: %s\n", sqlite3_errmsg(db));

    return -1;
  }
  sqlite3_bind_int(stmt, 1, uid);
  sqlite3_bind_text(stmt, 2, first, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, last, -1, SQLITE_TRANSIENT);
  rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    printf("[db] step failed: %s\n", sqlite3_errmsg(db));
    sqlite3_finalize(stmt);

    return -1;
  }
  sqlite3_finalize(stmt);

  *out_uid = uid;
  printf("[db] inserted user '%s %s' uid=%d\n", first, last, *out_uid);

  return 0;
}

int db_remove_user(int uid) {
  sqlite3_stmt *stmt;
  if (!db)

    return -1;
  int rc =
      sqlite3_prepare_v2(db, "DELETE FROM users WHERE uid=?;", -1, &stmt, NULL);
  if (rc != SQLITE_OK)

    return -1;
  sqlite3_bind_int(stmt, 1, uid);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);
  if (rc != SQLITE_DONE)

    return -1;

  return 0;
}

int db_get_uid_by_name(const char *first, const char *last, int **uids,
                       int *count) {
  sqlite3_stmt *stmt;
  if (!db)

    return -1;
  sqlite3_prepare_v2(db, "SELECT uid FROM users WHERE first=? AND last=?;", -1,
                     &stmt, NULL);
  sqlite3_bind_text(stmt, 1, first, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, last, -1, SQLITE_TRANSIENT);
  int *arr = malloc(sizeof(int) * 10); // temporary array
  int idx = 0;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    arr[idx++] = sqlite3_column_int(stmt, 0);
  }
  sqlite3_finalize(stmt);
  *uids = arr;
  *count = idx;

  return idx > 0 ? 0 : -1;
}

int db_get_points(int uid, int *points) {
  sqlite3_stmt *stmt;
  if (!db)

    return -1;
  sqlite3_prepare_v2(db, "SELECT points FROM users WHERE uid=?;", -1, &stmt,
                     NULL);
  sqlite3_bind_int(stmt, 1, uid);
  int rc = -1;
  if (sqlite3_step(stmt) == SQLITE_ROW) {
    *points = sqlite3_column_int(stmt, 0);
    rc = 0;
  }
  sqlite3_finalize(stmt);

  return rc;
}

int db_set_points(int uid, int points) {
  sqlite3_stmt *stmt;
  if (!db)

    return -1;
  int rc = sqlite3_prepare_v2(db, "UPDATE users SET points=? WHERE uid=?;", -1,
                              &stmt, NULL);
  if (rc != SQLITE_OK)

    return -1;
  sqlite3_bind_int(stmt, 1, points);
  sqlite3_bind_int(stmt, 2, uid);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  return rc == SQLITE_DONE ? 0 : -1;
}

int db_add_points(int uid, int delta) {
  sqlite3_stmt *stmt;
  if (!db)

    return -1;
  int rc = sqlite3_prepare_v2(
      db, "UPDATE users SET points=points+? WHERE uid=?;", -1, &stmt, NULL);
  if (rc != SQLITE_OK)

    return -1;
  sqlite3_bind_int(stmt, 1, delta);
  sqlite3_bind_int(stmt, 2, uid);
  rc = sqlite3_step(stmt);
  sqlite3_finalize(stmt);

  return rc == SQLITE_DONE ? 0 : -1;
}

int db_remove_key(const char *key) {
  if (!db || !key)

    return -1;
  sqlite3_stmt *stmt = NULL;
  int rc = sqlite3_prepare_v2(db, "SELECT id, key_hash, salt FROM keys;", -1,
                              &stmt, NULL);
  if (rc != SQLITE_OK)

    return -1;
  const uint32_t iterations = 100000;
  int found_id = -1;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    int id = sqlite3_column_int(stmt, 0);
    const unsigned char *kh = sqlite3_column_text(stmt, 1);
    const unsigned char *salt_hex = sqlite3_column_text(stmt, 2);
    if (!kh || !salt_hex)
      continue;
    size_t salt_hex_len = strlen((const char *)salt_hex);
    size_t salt_bytes = salt_hex_len / 2;
    uint8_t salt_raw[64];
    if (salt_bytes > sizeof(salt_raw))
      continue;
    if (hex_decode((const char *)salt_hex, salt_raw, salt_bytes) != 0)
      continue;

    uint8_t dk[32];
    if (pbkdf2_hmac_sha256((const uint8_t *)key, strlen(key), salt_raw,
                           salt_bytes, iterations, dk, sizeof(dk)) != 0)
      continue;
    char dk_hex[65];
    hex_encode(dk, sizeof(dk), dk_hex, sizeof(dk_hex));
    if (strcmp(dk_hex, (const char *)kh) == 0) {
      found_id = id;
      break;
    }
  }
  sqlite3_finalize(stmt);
  if (found_id < 0)

    return -1;
  sqlite3_stmt *del = NULL;
  rc = sqlite3_prepare_v2(db, "DELETE FROM keys WHERE id=?;", -1, &del, NULL);
  if (rc != SQLITE_OK)

    return -1;
  sqlite3_bind_int(del, 1, found_id);
  rc = sqlite3_step(del);
  sqlite3_finalize(del);

  return rc == SQLITE_DONE ? 0 : -1;
}

int db_get_all_users(char **out_json) {
  if (!db)

    return -1;
  sqlite3_stmt *stmt;
  int rc = sqlite3_prepare_v2(db, "SELECT uid,first,last,points FROM users;",
                              -1, &stmt, NULL);
  if (rc != SQLITE_OK)

    return -1;

  struct json_object *arr = json_object_new_array();
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    int uid = sqlite3_column_int(stmt, 0);
    const unsigned char *first = sqlite3_column_text(stmt, 1);
    const unsigned char *last = sqlite3_column_text(stmt, 2);
    int points = sqlite3_column_int(stmt, 3);

    struct json_object *obj = json_object_new_object();
    json_object_object_add(obj, "uid", json_object_new_int(uid));
    json_object_object_add(
        obj, "first", json_object_new_string(first ? (const char *)first : ""));
    json_object_object_add(
        obj, "last", json_object_new_string(last ? (const char *)last : ""));
    json_object_object_add(obj, "points", json_object_new_int(points));
    json_object_array_add(arr, obj);
  }
  const char *s = json_object_to_json_string(arr);
  *out_json = strdup(s ? s : "[]");
  json_object_put(arr);
  sqlite3_finalize(stmt);

  return 0;
}
