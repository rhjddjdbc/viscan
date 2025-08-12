#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <ftw.h>

#include "hash_utils.h"
#include "hdb_parser.h"
#include "quarantine.h"

static int verbose = 0;
static int infected_count = 0;
static int clean_count = 0;

void scan_file(const char *filepath) {
    if (verbose) printf("[*] Scanning file: %s\n", filepath);

    char md5_hash[33];
    if (compute_md5(filepath, md5_hash) != 0) {
        printf("[!] Error reading file: %s\n", filepath);
        return;
    }

    if (verbose) printf("    MD5: %s\n", md5_hash);

    if (hash_in_signatures(md5_hash)) {
        printf("[!] INFECTED: %s is listed in the signature database.\n", filepath);
        quarantine_file(filepath, md5_hash, verbose);
        infected_count++;
    } else {
        if (verbose) printf("[+] Clean: No match found.\n");
        clean_count++;
    }

    if (verbose) printf("\n");
}

static int nftw_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;     // unused parameter to avoid compiler warnings
    (void)ftwbuf; // unused parameter to avoid compiler warnings

    if (typeflag == FTW_F) {
        scan_file(fpath);
    }
    return 0;
}

int main(int argc, char **argv) {
    int file_start = 1;

    if (argc > 1 && strcmp(argv[1], "--verbose") == 0) {
        verbose = 1;
        file_start = 2;
    }

    if (argc - file_start < 1) {
        printf("Usage: %s [--verbose] <file_or_dir1> [file_or_dir2 ...]\n", argv[0]);
        return 1;
    }

    // Pass verbose flag to hdb_parser
    set_verbose(verbose);

    // Load signature databases
    load_signatures_from_database();

    if (verbose) {
        printf("[*] Arguments to scan:\n");
        for (int i = file_start; i < argc; i++) {
            printf(" - %s\n", argv[i]);
        }
        printf("\n");
    }

    for (int i = file_start; i < argc; i++) {
        struct stat path_stat;
        if (stat(argv[i], &path_stat) != 0) {
            perror("Error stating path");
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            if (verbose) printf("[*] Recursively scanning directory: %s\n", argv[i]);
            if (nftw(argv[i], nftw_callback, 20, 0) != 0) {
                perror("Error walking directory tree");
            }
        } else if (S_ISREG(path_stat.st_mode)) {
            scan_file(argv[i]);
        } else {
            if (verbose) printf("[!] Skipping non-regular file: %s\n", argv[i]);
        }
    }

    printf("=== Scan Summary ===\n");
    printf("Total files scanned: %d\n", infected_count + clean_count);
    printf("Infected files    : %d\n", infected_count);
    printf("Clean files       : %d\n", clean_count);

    free_signatures();
    return 0;
}

