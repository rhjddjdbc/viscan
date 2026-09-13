#include "hdb_parser.h"
#include "ac_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>

/* ================================================================
 * MD5 signature / whitelist hash tables
 * ================================================================ */

#define HASH_BITS        21u
#define HASH_SIZE        (1u << HASH_BITS)
#define HASH_MASK        (HASH_SIZE - 1u)

typedef struct hash_node {
    char md5[33];
    struct hash_node *next;
} hash_node;

static hash_node **sig_table       = NULL;
static hash_node **whitelist_table = NULL;
static size_t      sig_count       = 0;
static size_t      whitelist_count = 0;

/* ================================================================
 * Pattern signatures (opt-in)
 * ================================================================ */

/*
 * Only .ndb is supported for pattern scanning. .ldb and .mdb are
 * logical signatures that require a real expression evaluator; treating
 * their sub-signatures as standalone patterns produces unacceptable
 * false-positive rates, so we skip them entirely.
 */

#define MIN_PATTERN_BYTES 32u
#define MAX_PATTERN_COUNT 200000u

typedef struct {
    unsigned char *bytes;
    unsigned char *mask;
    size_t         len;
    long           offset;
    char          *name;
} logical_pattern;

typedef struct {
    int32_t logical_idx;
    int32_t run_offset;
    int32_t run_len;
} solid_run;

typedef struct {
    int32_t logical_idx;
    long    offset;
} fixed_pattern;

static logical_pattern *logical       = NULL;
static size_t           logical_count = 0;
static size_t           logical_cap   = 0;

static solid_run       *runs          = NULL;
static size_t           runs_count    = 0;
static size_t           runs_cap      = 0;

static fixed_pattern   *fixed_pats    = NULL;
static size_t           fixed_count   = 0;
static size_t           fixed_cap     = 0;

static unsigned char   *matched_flags = NULL;

static ac_engine       *ac            = NULL;
static int              ac_has_patterns = 0;

static int              verbose           = 0;
static int              pattern_scan_on   = 0;
static size_t           patterns_skipped  = 0;

void set_verbose(int v)      { verbose = v; }
void set_pattern_scan(int e) { pattern_scan_on = e; }

/* ================================================================
 * Small helpers
 * ================================================================ */

static int has_allowed_extension(const char *name) {
    static const char *exts[] = { ".hdb", ".fp", ".ndb" };
    size_t len = strlen(name);
    for (size_t i = 0; i < sizeof(exts) / sizeof(exts[0]); i++) {
        size_t el = strlen(exts[i]);
        if (len > el && strcmp(name + len - el, exts[i]) == 0) return 1;
    }
    return 0;
}

static unsigned int fnv1a(const char *s) {
    unsigned int h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h & HASH_MASK;
}

static void hash_insert(hash_node **table, const char *md5) {
    unsigned int idx = fnv1a(md5);
    hash_node *n = malloc(sizeof(*n));
    if (!n) return;
    strncpy(n->md5, md5, 32);
    n->md5[32] = '\0';
    n->next = table[idx];
    table[idx] = n;
}

static int hash_lookup(hash_node **table, const char *md5) {
    if (!table) return 0;
    unsigned int idx = fnv1a(md5);
    for (hash_node *n = table[idx]; n; n = n->next) {
        if (strcmp(n->md5, md5) == 0) return 1;
    }
    return 0;
}

static void hash_free(hash_node **table) {
    if (!table) return;
    for (size_t i = 0; i < HASH_SIZE; i++) {
        hash_node *n = table[i];
        while (n) { hash_node *x = n->next; free(n); n = x; }
    }
    free(table);
}

static int parse_hex_pattern(const char *hex,
                             unsigned char **out_bytes,
                             unsigned char **out_mask,
                             size_t *out_len) {
    if (!hex) return -1;
    size_t hex_len = strlen(hex);
    if (hex_len == 0 || (hex_len % 2) != 0) return -1;

    size_t n = hex_len / 2;
    unsigned char *b = malloc(n);
    unsigned char *m = malloc(n);
    if (!b || !m) { free(b); free(m); return -1; }

    for (size_t i = 0; i < n; i++) {
        char c1 = hex[i * 2];
        char c2 = hex[i * 2 + 1];
        if (c1 == '?' && c2 == '?') { b[i] = 0; m[i] = 0x00; }
        else if (isxdigit((unsigned char)c1) && isxdigit((unsigned char)c2)) {
            char tmp[3] = { c1, c2, 0 };
            b[i] = (unsigned char)strtol(tmp, NULL, 16);
            m[i] = 0xFF;
        } else { free(b); free(m); return -1; }
    }
    *out_bytes = b;
    *out_mask  = m;
    *out_len   = n;
    return 0;
}

/* ================================================================
 * Pattern registration
 * ================================================================ */

static void add_pattern_own(unsigned char *bytes, unsigned char *mask,
                            size_t len, long offset, const char *name) {
    if (len == 0) { free(bytes); free(mask); return; }

    if (len < MIN_PATTERN_BYTES) {
        patterns_skipped++;
        free(bytes); free(mask);
        return;
    }
    if (logical_count >= MAX_PATTERN_COUNT) {
        patterns_skipped++;
        free(bytes); free(mask);
        return;
    }

    if (logical_count == logical_cap) {
        size_t nc = logical_cap ? logical_cap * 2 : 1024;
        logical_pattern *p = realloc(logical, nc * sizeof(*p));
        if (!p) { free(bytes); free(mask); return; }
        logical = p;
        logical_cap = nc;
    }

    int32_t idx = (int32_t)logical_count;
    logical_pattern *lp = &logical[idx];
    lp->bytes  = bytes;
    lp->mask   = mask;
    lp->len    = len;
    lp->offset = offset;
    lp->name   = name ? strdup(name) : NULL;
    logical_count++;

    if (offset >= 0) {
        if (fixed_count == fixed_cap) {
            size_t nc = fixed_cap ? fixed_cap * 2 : 64;
            fixed_pattern *p = realloc(fixed_pats, nc * sizeof(*p));
            if (!p) return;
            fixed_pats = p;
            fixed_cap  = nc;
        }
        fixed_pats[fixed_count].logical_idx = idx;
        fixed_pats[fixed_count].offset      = offset;
        fixed_count++;
        return;
    }

    size_t i = 0;
    while (i < len) {
        while (i < len && mask[i] != 0xFF) i++;
        size_t start = i;
        while (i < len && mask[i] == 0xFF) i++;
        size_t rlen = i - start;
        if (rlen == 0) continue;

        if (runs_count == runs_cap) {
            size_t nc = runs_cap ? runs_cap * 2 : 1024;
            solid_run *p = realloc(runs, nc * sizeof(*p));
            if (!p) return;
            runs = p;
            runs_cap = nc;
        }
        runs[runs_count].logical_idx = idx;
        runs[runs_count].run_offset  = (int32_t)start;
        runs[runs_count].run_len     = (int32_t)rlen;
        int32_t ridx = (int32_t)runs_count;
        runs_count++;

        if (ac_add(ac, bytes + start, rlen, ridx) == 0) ac_has_patterns = 1;
    }
}

static void add_hex_pattern(const char *hex, long offset, const char *name) {
    unsigned char *b, *m;
    size_t len;
    if (parse_hex_pattern(hex, &b, &m, &len) != 0) return;
    add_pattern_own(b, m, len, offset, name);
}

/* ================================================================
 * File parsers
 * ================================================================ */

static void load_hdb_file(const char *path, int whitelist) {
    FILE *f = fopen(path, "r");
    if (!f) { if (verbose) printf("[!] Cannot open %s\n", path); return; }

    char line[512];
    size_t loaded = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        char *sep = strchr(line, ':');
        if (!sep) continue;
        *sep = '\0';
        if (strlen(line) != 32) continue;

        if (whitelist) { hash_insert(whitelist_table, line); whitelist_count++; }
        else           { hash_insert(sig_table,       line); sig_count++;       }
        loaded++;
    }
    fclose(f);
    if (verbose)
        printf("[*] Loaded %zu %s entries from %s\n",
               loaded, whitelist ? "whitelist" : "hash", path);
}

/*
 * .ndb: Name:Target:Offset:HexSig[:MinFL:MaxFL]
 *
 * We only accept Target == 0 ("any"). Target-specific signatures
 * (PE, OLE2, HTML, ...) would need a real file-type dispatcher on
 * the scanning side, which we do not have. Accepting them here would
 * match the raw bytes of unrelated file formats.
 */
static void load_ndb_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { if (verbose) printf("[!] Cannot open %s\n", path); return; }

    char line[4096];
    size_t parsed = 0, skipped_target = 0, skipped_len = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0') continue;

        /* Split into up to 6 colon-separated fields. */
        char *fields[6] = {0};
        int   nf = 0;
        char *cur = line;
        for (int i = 0; i < 6; i++) {
            fields[nf++] = cur;
            char *colon = strchr(cur, ':');
            if (!colon) break;
            *colon = '\0';
            cur = colon + 1;
        }
        if (nf < 4) continue;

        /* Target type: accept only 0 ("any"). */
        char *tend = NULL;
        long target = strtol(fields[1], &tend, 10);
        if (tend == fields[1] || *tend != '\0' || target != 0) {
            skipped_target++;
            continue;
        }

        /* Offset: "*" or a non-negative integer. */
        long offset = -1;
        if (strcmp(fields[2], "*") != 0) {
            char *oend = NULL;
            long v = strtol(fields[2], &oend, 10);
            if (oend == fields[2] || *oend != '\0' || v < 0) continue;
            offset = v;
        }

        size_t before = logical_count;
        add_hex_pattern(fields[3], offset, fields[0]);
        if (logical_count == before) skipped_len++;
        else parsed++;
    }
    fclose(f);
    if (verbose)
        printf("[*] NDB %s: parsed=%zu, skipped(target)=%zu, "
               "skipped(short/invalid)=%zu\n",
               path, parsed, skipped_target, skipped_len);
}

/* ================================================================
 * AC search glue
 * ================================================================ */

typedef struct {
    const unsigned char *data;
    size_t               len;
} ac_ctx;

static int verify_logical(const logical_pattern *lp,
                          const unsigned char *data, size_t data_len,
                          size_t start_pos) {
    if (start_pos + lp->len > data_len) return 0;
    for (size_t i = 0; i < lp->len; i++) {
        if (lp->mask[i] &&
            (data[start_pos + i] & lp->mask[i]) != lp->bytes[i]) return 0;
    }
    return 1;
}

static int ac_callback(int32_t run_id, size_t end_pos, void *user) {
    ac_ctx *ctx = user;
    if (run_id < 0 || (size_t)run_id >= runs_count) return 0;

    const solid_run *r = &runs[run_id];
    int32_t li = r->logical_idx;
    if (matched_flags[li]) return 0;

    if (end_pos < (size_t)r->run_len) return 0;
    size_t run_start = end_pos - (size_t)r->run_len;
    if (run_start < (size_t)r->run_offset) return 0;
    size_t lp_start = run_start - (size_t)r->run_offset;

    const logical_pattern *lp = &logical[li];
    if (verify_logical(lp, ctx->data, ctx->len, lp_start)) {
        matched_flags[li] = 1;
        if (verbose && lp->name)
            printf("    Pattern match: %s\n", lp->name);
    }
    return 0;
}

/* ================================================================
 * Public API
 * ================================================================ */

int load_signatures_from_database(void) {
    if (!sig_table)       sig_table       = calloc(HASH_SIZE, sizeof(hash_node *));
    if (!whitelist_table) whitelist_table = calloc(HASH_SIZE, sizeof(hash_node *));
    if (!sig_table || !whitelist_table) {
        fprintf(stderr, "[!] Out of memory initializing hash tables\n");
        return -1;
    }

    if (pattern_scan_on) {
        if (!ac) ac = ac_create();
        if (!ac) {
            fprintf(stderr, "[!] Could not create AC engine\n");
            return -1;
        }
    }

    DIR *d = opendir("database");
    if (!d) {
        if (verbose) printf("[!] Could not open database directory\n");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        if (!has_allowed_extension(entry->d_name)) continue;

        char path[1024];
        snprintf(path, sizeof(path), "database/%s", entry->d_name);
        const char *ext = strrchr(entry->d_name, '.');

        if (strcmp(ext, ".hdb") == 0)      load_hdb_file(path, 0);
        else if (strcmp(ext, ".fp") == 0)  load_hdb_file(path, 1);
        else if (strcmp(ext, ".ndb") == 0) {
            if (pattern_scan_on) load_ndb_file(path);
        }
    }
    closedir(d);

    if (pattern_scan_on && ac_build(ac) != 0) {
        fprintf(stderr, "[!] Failed to build AC automaton\n");
        return -1;
    }

    if (logical_count > 0) {
        matched_flags = calloc(logical_count, 1);
        if (!matched_flags) {
            fprintf(stderr, "[!] Out of memory for match flags\n");
            return -1;
        }
    }

    if (verbose) {
        printf("[*] MD5 signatures     : %zu\n", sig_count);
        printf("[*] Whitelist entries  : %zu\n", whitelist_count);
        if (pattern_scan_on) {
            printf("[*] Logical patterns   : %zu\n", logical_count);
            printf("[*] Solid runs (AC)    : %zu\n", runs_count);
            printf("[*] Fixed-offset pats  : %zu\n", fixed_count);
            printf("[*] Patterns skipped   : %zu\n", patterns_skipped);
        } else {
            printf("[*] Pattern scan       : disabled "
                   "(use --pattern-scan to enable)\n");
        }
    }

    if (sig_count == 0) {
        fprintf(stderr, "[!] No usable signatures found in database/\n");
        return -1;
    }
    return 0;
}

int hash_in_signatures(const char *hash) {
    if (hash_lookup(whitelist_table, hash)) return 0;
    return hash_lookup(sig_table, hash);
}

int file_has_pattern_match(const char *path) {
    if (!pattern_scan_on) return 0;
    if (logical_count == 0) return 0;

    FILE *f = fopen(path, "rb");
    if (!f) return 0;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 0; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return 0; }
    if ((unsigned long)sz > 100UL * 1024 * 1024) {
        if (verbose) printf("    [~] File too large for pattern scan\n");
        fclose(f);
        return 0;
    }
    rewind(f);

    unsigned char *data = malloc((size_t)sz);
    if (!data) { fclose(f); return 0; }
    size_t nread = fread(data, 1, (size_t)sz, f);
    fclose(f);
    if (nread != (size_t)sz) { free(data); return 0; }

    memset(matched_flags, 0, logical_count);

    if (ac_has_patterns) {
        ac_ctx ctx = { data, (size_t)sz };
        ac_search(ac, data, (size_t)sz, ac_callback, &ctx);
    }

    for (size_t i = 0; i < fixed_count; i++) {
        int32_t li = fixed_pats[i].logical_idx;
        if (matched_flags[li]) continue;
        long off = fixed_pats[i].offset;
        if (off < 0) continue;
        const logical_pattern *lp = &logical[li];
        if ((size_t)off + lp->len > (size_t)sz) continue;
        if (verify_logical(lp, data, (size_t)sz, (size_t)off)) {
            matched_flags[li] = 1;
            if (verbose && lp->name)
                printf("    Pattern match: %s\n", lp->name);
        }
    }

    int any = 0;
    for (size_t i = 0; i < logical_count; i++)
        if (matched_flags[i]) { any = 1; break; }

    free(data);
    return any;
}

void free_signatures(void) {
    hash_free(sig_table);       sig_table = NULL;
    hash_free(whitelist_table); whitelist_table = NULL;

    for (size_t i = 0; i < logical_count; i++) {
        free(logical[i].bytes);
        free(logical[i].mask);
        free(logical[i].name);
    }
    free(logical); logical = NULL; logical_count = logical_cap = 0;

    free(runs);       runs       = NULL; runs_count   = runs_cap   = 0;
    free(fixed_pats); fixed_pats = NULL; fixed_count  = fixed_cap  = 0;
    free(matched_flags); matched_flags = NULL;

    if (ac) { ac_destroy(ac); ac = NULL; }
    ac_has_patterns = 0;

    sig_count = 0;
    whitelist_count = 0;
    patterns_skipped = 0;
}
