#include "db.h"
#include "server.h"

#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

static volatile sig_atomic_t keep_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

int main() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    printf("Starting server...\n");

    // Use a restrictive umask while creating the DB file to avoid world-readable
    // DB files
    mode_t old_umask = umask(S_IWGRP | S_IWOTH);
    if(db_init("data.db") != 0) {
        umask(old_umask);
        fprintf(stderr, "Failed to initialize database\n");

        return 1;
    }
    umask(old_umask);

    // Start server on port 8080
    if(start_server(8080) != 0) {
        db_close();

        return 1;
    }

    // Keep running until Ctrl+C
    while(keep_running) {
        struct timespec ts = {0, 100000000}; // 100ms
        nanosleep(&ts, NULL);
    }

    printf("\nStopping server...\n");
    stop_server();
    db_close();
    printf("Server stopped.\n");

    return 0;
}
