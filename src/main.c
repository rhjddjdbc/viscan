#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <ftw.h>

#include "hash_utils.h"
#include "hdb_parser.h"
#include "quarantine.h"
#include "update_database.h"

static int verbose = 0;
static int infected_count = 0;
static int clean_count = 0;
static int error_count = 0;

/* Quarantine subcommand state */
static int   cmd_qlist      = 0;
static int   cmd_qrestore   = 0;
static int   cmd_qclean     = 0;
static const char *qrestore_id   = NULL;
static const char *qrestore_dest = NULL;
static int   qclean_days    = 30;

static int scan_file(const char *filepath) {
    if (verbose) printf("[*] Scanning file: %s\n", filepath);

    char md5_hash[33];
    if (compute_md5(filepath, md5_hash) != 0) {
        printf("[!] Error reading file: %s\n", filepath);
        error_count++;
        return -1;
    }

    if (verbose) printf("    MD5: %s\n", md5_hash);

    const char *reason = NULL;

    if (hash_in_signatures(md5_hash)) {
        reason = "MD5 signature match";
    } else if (file_has_pattern_match(filepath)) {
        reason = "Content pattern match";
    }

    if (reason) {
        printf("[!] INFECTED: %s (%s)\n", filepath, reason);
        if (quarantine_file(filepath, md5_hash, reason, verbose) != 0) {
            fprintf(stderr, "[!] Quarantine failed for %s\n", filepath);
            error_count++;
        }
        infected_count++;
        return 1;
    }

    if (verbose) printf("[+] Clean: No match found.\n\n");
    clean_count++;
    return 0;
}

static int nftw_callback(const char *fpath, const struct stat *sb,
                         int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_F) {
        scan_file(fpath);
    }
    return 0;
}

static void print_usage(const char *prog) {
    printf("Usage:\n"
           "  %s [OPTIONS] <file_or_dir1> [file_or_dir2 ...]\n"
           "  %s --quarantine-list\n"
           "  %s --quarantine-restore <id> [--dest <path>]\n"
           "  %s --quarantine-clean [--days N]\n"
           "\n"
           "Scan options:\n"
           "  --verbose             Print detailed scanning information\n"
           "  --force-update        Force database update even if not expired\n"
           "  --pattern-scan        Enable best-effort pattern matching\n"
           "                        (noisy; produces false positives on\n"
           "                        untrusted binary input — use for research\n"
           "                        only, do NOT auto-quarantine in this mode)\n"
           "  --help                Show this help message and exit\n"
           "\n"
           "Quarantine options:\n"
           "  --quarantine-list     List all entries in the vault\n"
           "  --quarantine-restore  Restore an entry by ID\n"
           "  --dest <path>         Destination for --quarantine-restore\n"
           "                        (default: recorded original path)\n"
           "  --quarantine-clean    Delete old entries from the vault\n"
           "  --days <n>            Age threshold for --quarantine-clean\n"
           "                        (default 30; 0 removes everything)\n"
           "\n"
           "Examples:\n"
           "  %s file.txt\n"
           "  %s --verbose /home/user/downloads\n"
           "  %s --force-update /var/www/html\n"
           "  %s --pattern-scan --verbose /tmp/samples\n"
           "  %s --quarantine-list\n"
           "  %s --quarantine-restore 20260214T153012_ab12cd34\n"
           "  %s --quarantine-restore 20260214T153012_ab12cd34 --dest /tmp/recovered.bin\n"
           "  %s --quarantine-clean --days 7\n",
           prog, prog, prog, prog,
           prog, prog, prog, prog, prog, prog, prog, prog);
}

int main(int argc, char **argv) {
    int force_update = 0;
    int pattern_scan = 0;

    char **files = calloc((size_t)argc, sizeof(char *));
    if (!files) { fprintf(stderr, "Out of memory\n"); return 1; }
    int nfiles = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "--help") == 0) {
            print_usage(argv[0]);
            free(files);
            return 0;
        } else if (strcmp(a, "--verbose") == 0) {
            verbose = 1;
        } else if (strcmp(a, "--force-update") == 0) {
            force_update = 1;
        } else if (strcmp(a, "--pattern-scan") == 0) {
            pattern_scan = 1;
        } else if (strcmp(a, "--quarantine-list") == 0) {
            cmd_qlist = 1;
        } else if (strcmp(a, "--quarantine-restore") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[!] --quarantine-restore needs an <id>\n");
                free(files); return 1;
            }
            cmd_qrestore = 1;
            qrestore_id  = argv[++i];
        } else if (strcmp(a, "--dest") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[!] --dest needs a <path>\n");
                free(files); return 1;
            }
            qrestore_dest = argv[++i];
        } else if (strcmp(a, "--quarantine-clean") == 0) {
            cmd_qclean = 1;
        } else if (strcmp(a, "--days") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "[!] --days needs a number\n");
                free(files); return 1;
            }
            qclean_days = atoi(argv[++i]);
            if (qclean_days < 0) qclean_days = 0;
        } else if (a[0] == '-' && a[1] != '\0') {
            fprintf(stderr, "Unknown option: %s\n", a);
            print_usage(argv[0]);
            free(files);
            return 1;
        } else {
            files[nfiles++] = argv[i];
        }
    }

    /* Quarantine subcommands short-circuit scanning. */
    if (cmd_qlist) {
        int rc = quarantine_list();
        free(files);
        return rc == 0 ? 0 : 1;
    }
    if (cmd_qrestore) {
        int rc = quarantine_restore(qrestore_id, qrestore_dest, verbose);
        free(files);
        return rc == 0 ? 0 : 1;
    }
    if (cmd_qclean) {
        int rc = quarantine_clean(qclean_days, verbose);
        free(files);
        return rc == 0 ? 0 : 1;
    }

    if (nfiles == 0) {
        print_usage(argv[0]);
        free(files);
        return 1;
    }

    if (update_if_needed(force_update) != 0) {
        fprintf(stderr, "[!] Failed to update the database.\n");
        free(files);
        return 1;
    }

    set_verbose(verbose);
    set_pattern_scan(pattern_scan);

    if (pattern_scan) {
        fprintf(stderr,
            "[!] Pattern scan is enabled. This is a best-effort matcher\n"
            "[!] and will produce false positives on untrusted binary files.\n"
            "[!] Use only for research. Do NOT auto-quarantine in this mode.\n");
    }

    if (load_signatures_from_database() != 0) {
        fprintf(stderr, "[!] Failed to load signature database.\n");
        free(files);
        return 1;
    }

    if (verbose) {
        printf("[*] Arguments to scan:\n");
        for (int i = 0; i < nfiles; i++) printf(" - %s\n", files[i]);
        printf("\n");
    }

    for (int i = 0; i < nfiles; i++) {
        struct stat path_stat;
        if (stat(files[i], &path_stat) != 0) {
            perror("Error stating path");
            error_count++;
            continue;
        }

        if (S_ISDIR(path_stat.st_mode)) {
            if (verbose)
                printf("[*] Recursively scanning directory: %s\n", files[i]);
            if (nftw(files[i], nftw_callback, 20, FTW_PHYS) != 0) {
                perror("Error walking directory tree");
                error_count++;
            }
        } else if (S_ISREG(path_stat.st_mode)) {
            scan_file(files[i]);
        } else {
            if (verbose)
                printf("[!] Skipping non-regular file: %s\n", files[i]);
        }
    }

    printf("=== Scan Summary ===\n");
    printf("Total files scanned: %d\n", infected_count + clean_count);
    printf("Infected files    : %d\n", infected_count);
    printf("Clean files       : %d\n", clean_count);
    if (error_count > 0)
        printf("Errors            : %d\n", error_count);

    free_signatures();
    free(files);

    return infected_count > 0 ? 1 : 0;
}
