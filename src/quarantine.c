#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

void quarantine_file(const char *filepath, const char *md5, int verbose) {
    struct stat st;
    if (stat(filepath, &st) != 0) {
        perror("Failed to get file info");
        return;
    }

    system("mkdir -p quarantine");

    const char *filename = strrchr(filepath, '/');
    if (!filename) filename = filepath;
    else filename++;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char datetime[64];
    strftime(datetime, sizeof(datetime), "%Y%m%d_%H%M%S", tm);

    char log_path[512];
    snprintf(log_path, sizeof(log_path), "quarantine/%s_%s.log", filename, datetime);

    FILE *log = fopen(log_path, "w");
    if (!log) {
        perror("Failed to open quarantine log");
        return;
    }

    fprintf(log, "=== QUARANTINE REPORT ===\n");
    fprintf(log, "Filename     : %s\n", filename);
    fprintf(log, "Absolute Path: %s\n", realpath(filepath, NULL));
    fprintf(log, "Size (bytes) : %ld\n", st.st_size);
    fprintf(log, "MD5          : %s\n", md5);
    fprintf(log, "Scan Time    : %s", ctime(&now));
    fprintf(log, "\n--- FILE CONTENT (hex) ---\n");

    FILE *f = fopen(filepath, "rb");
    if (!f) {
        fprintf(log, "[!] Cannot read file content.\n");
    } else {
        unsigned char buf[16];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            for (size_t i = 0; i < n; i++) {
                fprintf(log, "%02X ", buf[i]);
            }
            fprintf(log, "\n");
        }
        fclose(f);
    }
    fclose(log);

    if (remove(filepath) == 0) {
        if (verbose)
            printf("File '%s' deleted and quarantined.\n", filepath);
    } else {
        perror("Error deleting file");
    }
}

