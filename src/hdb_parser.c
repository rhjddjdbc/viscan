#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define MAX_SIGS 5000000

static char *signatures[MAX_SIGS];
static int sig_count = 0;
static int verbose = 0;  // Set by main.c

void set_verbose(int v) {
    verbose = v;
}

int has_allowed_extension(const char *filename) {
    const char *allowed_exts[] = {
        ".hdb", ".ndb", ".ldb", ".mdb", ".fp"
    };
    size_t len = strlen(filename);

    for (size_t i = 0; i < sizeof(allowed_exts) / sizeof(allowed_exts[0]); i++) {
        size_t ext_len = strlen(allowed_exts[i]);
        if (len > ext_len && strcmp(filename + len - ext_len, allowed_exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}


void load_hdb_file(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        if (verbose) printf("[!] Could not open signature file: %s\n", path);
        return;
    }

    if (verbose) printf("[*] Loading HDB file: %s\n", path);

    char line[512];
    int loaded = 0;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        char *sep = strchr(line, ':');
        if (!sep) continue;

        *sep = '\0';
        char *md5 = line;

        if (strlen(md5) == 32) {
            if (sig_count < MAX_SIGS) {
                signatures[sig_count++] = strdup(md5);
                loaded++;
            }
        }
    }

    fclose(file);
    if (verbose) printf("[*] Loaded %d signatures from %s\n", loaded, path);
}

void load_fp_file(const char *path) {
    load_hdb_file(path);
}

void load_ndb_file(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        if (verbose) printf("[!] Could not open signature file: %s\n", path);
        return;
    }

    if (verbose) printf("[*] Loading NDB file: %s\n", path);

    char line[1024];
    int loaded = 0;

    while (fgets(line, sizeof(line), file)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#') continue;

        char *last_colon = strrchr(line, ':');
        if (!last_colon || strlen(last_colon + 1) < 8) continue;

        char *pattern = last_colon + 1;

        if (sig_count < MAX_SIGS) {
            signatures[sig_count++] = strdup(pattern);
            loaded++;
        }
    }

    fclose(file);
    if (verbose) printf("[*] Loaded %d pattern signatures from %s\n", loaded, path);
}

void load_ldb_file(const char *path) {
    load_ndb_file(path);
}

void load_mdb_file(const char *path) {
    load_ndb_file(path);
}


void load_signature_file(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return;

    if (strcmp(ext, ".hdb") == 0) {
        load_hdb_file(path);
    } else if (strcmp(ext, ".fp") == 0) {
        load_fp_file(path);
    } else if (strcmp(ext, ".ndb") == 0) {
        load_ndb_file(path);
    } else if (strcmp(ext, ".ldb") == 0) {
        load_ldb_file(path);
    } else if (strcmp(ext, ".mdb") == 0) {
        load_mdb_file(path);
    } else {
        if (verbose) printf("[~] Skipping unsupported file: %s\n", path);
    }
}


void load_signatures_from_database() {
    DIR *d = opendir("database");
    if (!d) {
        if (verbose) printf("[!] Could not open database directory\n");
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (has_allowed_extension(entry->d_name)) {
            char path[512];
            snprintf(path, sizeof(path), "database/%s", entry->d_name);
            load_signature_file(path);
        }
    }

    closedir(d);

    if (verbose) {
        printf("[*] Total signatures loaded: %d\n", sig_count);
    }
}


int hash_in_signatures(const char *hash) {
    for (int i = 0; i < sig_count; i++) {
        if (strcmp(hash, signatures[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

void free_signatures() {
    for (int i = 0; i < sig_count; i++) {
        free(signatures[i]);
    }
    sig_count = 0;
}
