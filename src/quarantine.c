#include "quarantine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#define QUARANTINE_DIR "quarantine"
#define KEY_FILE       QUARANTINE_DIR "/.key"
#define KEY_LEN        32
#define NONCE_LEN      12
#define TAG_LEN        16
#define IO_CHUNK       (64u * 1024u)

/* ================================================================= */
/* Directory / key management                                        */
/* ================================================================= */

static int ensure_quarantine_dir(void) {
    struct stat st;
    if (stat(QUARANTINE_DIR, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "[!] '%s' exists and is not a directory\n", QUARANTINE_DIR);
        return -1;
    }
    if (mkdir(QUARANTINE_DIR, 0700) != 0) {
        perror("[!] Failed to create quarantine directory");
        return -1;
    }
    return 0;
}

static int load_or_create_key(unsigned char key[KEY_LEN]) {
    int fd = open(KEY_FILE, O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, key, KEY_LEN);
        close(fd);
        if (r == KEY_LEN) return 0;
        fprintf(stderr, "[!] Quarantine key is corrupt: %s\n", KEY_FILE);
        return -1;
    }

    if (RAND_bytes(key, KEY_LEN) != 1) {
        fprintf(stderr, "[!] RNG failure while generating key\n");
        return -1;
    }

    fd = open(KEY_FILE, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("[!] Cannot create quarantine key");
        return -1;
    }
    if (write(fd, key, KEY_LEN) != KEY_LEN) {
        perror("[!] Cannot write quarantine key");
        close(fd);
        unlink(KEY_FILE);
        return -1;
    }
    close(fd);
    return 0;
}

/* ================================================================= */
/* ID generation                                                     */
/* ================================================================= */

static void generate_id(char *out, size_t out_size) {
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);

    unsigned char rnd[4] = {0};
    RAND_bytes(rnd, sizeof(rnd));

    snprintf(out, out_size,
             "%04d%02d%02dT%02d%02d%02d_%02x%02x%02x%02x",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec,
             rnd[0], rnd[1], rnd[2], rnd[3]);
}

/* ================================================================= */
/* AES-256-GCM streaming                                             */
/* ================================================================= */

static int encrypt_stream(const unsigned char key[KEY_LEN],
                          FILE *in, FILE *out,
                          char sha256_out[65]) {
    unsigned char nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) return -1;
    if (fwrite(nonce, 1, NONCE_LEN, out) != NONCE_LEN) return -1;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX     *mctx = EVP_MD_CTX_new();
    if (!cctx || !mctx) {
        EVP_CIPHER_CTX_free(cctx);
        EVP_MD_CTX_free(mctx);
        return -1;
    }

    int ok = 0;
    if (EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_EncryptInit_ex(cctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DigestInit_ex(mctx, EVP_sha256(), NULL) != 1) goto done;

    unsigned char in_buf[IO_CHUNK];
    unsigned char out_buf[IO_CHUNK + 32];
    size_t n;

    while ((n = fread(in_buf, 1, sizeof(in_buf), in)) > 0) {
        if (EVP_DigestUpdate(mctx, in_buf, n) != 1) goto done;

        int len = 0;
        if (EVP_EncryptUpdate(cctx, out_buf, &len, in_buf, (int)n) != 1) goto done;
        if (len > 0 && fwrite(out_buf, 1, (size_t)len, out) != (size_t)len) goto done;
    }
    if (ferror(in)) goto done;

    int final_len = 0;
    if (EVP_EncryptFinal_ex(cctx, out_buf, &final_len) != 1) goto done;
    if (final_len > 0 && fwrite(out_buf, 1, (size_t)final_len, out) != (size_t)final_len) goto done;

    unsigned char tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;
    if (fwrite(tag, 1, TAG_LEN, out) != TAG_LEN) goto done;

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    if (EVP_DigestFinal_ex(mctx, digest, &dlen) != 1) goto done;
    for (unsigned int i = 0; i < dlen; i++)
        sprintf(sha256_out + i * 2, "%02x", digest[i]);
    sha256_out[dlen * 2] = '\0';

    ok = 1;

done:
    EVP_CIPHER_CTX_free(cctx);
    EVP_MD_CTX_free(mctx);
    return ok ? 0 : -1;
}

static int decrypt_stream(const unsigned char key[KEY_LEN],
                          FILE *in, FILE *out, const char *enc_path,
                          char sha256_out[65]) {
    unsigned char nonce[NONCE_LEN];
    if (fread(nonce, 1, NONCE_LEN, in) != NONCE_LEN) return -1;

    struct stat st;
    if (stat(enc_path, &st) != 0) return -1;
    if ((unsigned long)st.st_size < NONCE_LEN + TAG_LEN) return -1;

    long ct_len = (long)(st.st_size - NONCE_LEN - TAG_LEN);

    unsigned char tag[TAG_LEN];
    if (fseek(in, NONCE_LEN + ct_len, SEEK_SET) != 0) return -1;
    if (fread(tag, 1, TAG_LEN, in) != TAG_LEN) return -1;
    if (fseek(in, NONCE_LEN, SEEK_SET) != 0) return -1;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    EVP_MD_CTX     *mctx = EVP_MD_CTX_new();
    if (!cctx || !mctx) {
        EVP_CIPHER_CTX_free(cctx);
        EVP_MD_CTX_free(mctx);
        return -1;
    }

    int ok = 0;
    if (EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(cctx, NULL, NULL, key, nonce) != 1) goto done;
    if (EVP_DigestInit_ex(mctx, EVP_sha256(), NULL) != 1) goto done;

    unsigned char in_buf[IO_CHUNK];
    unsigned char out_buf[IO_CHUNK + 32];
    long remaining = ct_len;

    while (remaining > 0) {
        size_t to_read = (remaining < (long)sizeof(in_buf))
                       ? (size_t)remaining : sizeof(in_buf);
        size_t n = fread(in_buf, 1, to_read, in);
        if (n == 0) goto done;
        remaining -= (long)n;

        int len = 0;
        if (EVP_DecryptUpdate(cctx, out_buf, &len, in_buf, (int)n) != 1) goto done;
        if (len > 0) {
            if (EVP_DigestUpdate(mctx, out_buf, (size_t)len) != 1) goto done;
            if (fwrite(out_buf, 1, (size_t)len, out) != (size_t)len) goto done;
        }
    }

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) goto done;

    int final_len = 0;
    if (EVP_DecryptFinal_ex(cctx, out_buf, &final_len) != 1) goto done;
    if (final_len > 0) {
        if (EVP_DigestUpdate(mctx, out_buf, (size_t)final_len) != 1) goto done;
        if (fwrite(out_buf, 1, (size_t)final_len, out) != (size_t)final_len) goto done;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int  dlen = 0;
    if (EVP_DigestFinal_ex(mctx, digest, &dlen) != 1) goto done;
    for (unsigned int i = 0; i < dlen; i++)
        sprintf(sha256_out + i * 2, "%02x", digest[i]);
    sha256_out[dlen * 2] = '\0';

    ok = 1;

done:
    EVP_CIPHER_CTX_free(cctx);
    EVP_MD_CTX_free(mctx);
    return ok ? 0 : -1;
}

/* ================================================================= */
/* Metadata read/write                                               */
/* ================================================================= */

static int write_meta(const char *path, const quarantine_entry *e) {
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    chmod(path, 0600);

    fprintf(f, "id=%s\n",             e->id);
    fprintf(f, "original_path=%s\n",  e->original_path);
    fprintf(f, "md5=%s\n",            e->md5);
    fprintf(f, "sha256=%s\n",         e->sha256);
    fprintf(f, "size=%lld\n",         e->size);
    fprintf(f, "mode=%u\n",           e->mode);
    fprintf(f, "mtime=%lld\n",        e->mtime);
    fprintf(f, "uid=%d\n",            e->uid);
    fprintf(f, "gid=%d\n",            e->gid);
    fprintf(f, "quarantined_at=%lld\n", e->quarantined_at);
    fprintf(f, "reason=%s\n",         e->reason);

    if (fclose(f) != 0) return -1;
    return 0;
}

static int parse_meta(const char *path, quarantine_entry *e) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    memset(e, 0, sizeof(*e));

    char line[8192];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        const char *k = line;
        const char *v = eq + 1;

        if      (!strcmp(k, "id"))             snprintf(e->id, sizeof(e->id), "%s", v);
        else if (!strcmp(k, "original_path"))  snprintf(e->original_path, sizeof(e->original_path), "%s", v);
        else if (!strcmp(k, "md5"))            snprintf(e->md5, sizeof(e->md5), "%s", v);
        else if (!strcmp(k, "sha256"))         snprintf(e->sha256, sizeof(e->sha256), "%s", v);
        else if (!strcmp(k, "size"))           e->size  = atoll(v);
        else if (!strcmp(k, "mode"))           e->mode  = (unsigned int)strtoul(v, NULL, 10);
        else if (!strcmp(k, "mtime"))          e->mtime = atoll(v);
        else if (!strcmp(k, "uid"))            e->uid   = atoi(v);
        else if (!strcmp(k, "gid"))            e->gid   = atoi(v);
        else if (!strcmp(k, "quarantined_at")) e->quarantined_at = atoll(v);
        else if (!strcmp(k, "reason"))         snprintf(e->reason, sizeof(e->reason), "%s", v);
    }
    fclose(f);
    return 0;
}

/* ================================================================= */
/* Public API                                                        */
/* ================================================================= */

int quarantine_file(const char *filepath, const char *md5,
                    const char *reason, int verbose) {
    if (!filepath) return -1;
    if (ensure_quarantine_dir() != 0) return -1;

    unsigned char key[KEY_LEN];
    if (load_or_create_key(key) != 0) return -1;

    struct stat st;
    if (stat(filepath, &st) != 0) {
        fprintf(stderr, "[!] stat failed on '%s': %s\n",
                filepath, strerror(errno));
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[!] Not a regular file, refusing to quarantine: %s\n",
                filepath);
        return -1;
    }

    char id[64];
    generate_id(id, sizeof(id));

    char enc_path[1024];
    char meta_path[1024];
    snprintf(enc_path,  sizeof(enc_path),  QUARANTINE_DIR "/%s.enc",  id);
    snprintf(meta_path, sizeof(meta_path), QUARANTINE_DIR "/%s.meta", id);

    FILE *in = fopen(filepath, "rb");
    if (!in) {
        fprintf(stderr, "[!] Cannot open '%s': %s\n",
                filepath, strerror(errno));
        return -1;
    }

    FILE *out = fopen(enc_path, "wb");
    if (!out) {
        fclose(in);
        fprintf(stderr, "[!] Cannot create '%s': %s\n",
                enc_path, strerror(errno));
        return -1;
    }
    chmod(enc_path, 0600);

    char sha256[65];
    if (encrypt_stream(key, in, out, sha256) != 0) {
        fclose(in);
        fclose(out);
        unlink(enc_path);
        fprintf(stderr, "[!] Encryption failed for '%s'\n", filepath);
        return -1;
    }
    fclose(in);
    if (fclose(out) != 0) {
        unlink(enc_path);
        fprintf(stderr, "[!] Failed to flush '%s'\n", enc_path);
        return -1;
    }

    quarantine_entry e;
    memset(&e, 0, sizeof(e));
    snprintf(e.id, sizeof(e.id), "%s", id);

    char *abs = realpath(filepath, NULL);
    snprintf(e.original_path, sizeof(e.original_path), "%s",
             abs ? abs : filepath);
    free(abs);

    snprintf(e.md5,    sizeof(e.md5),    "%s", md5 ? md5 : "");
    snprintf(e.sha256, sizeof(e.sha256), "%s", sha256);
    snprintf(e.reason, sizeof(e.reason), "%s", reason ? reason : "");
    e.size           = (long long)st.st_size;
    e.mode           = (unsigned int)(st.st_mode & 07777);
    e.mtime          = (long long)st.st_mtime;
    e.uid            = (int)st.st_uid;
    e.gid            = (int)st.st_gid;
    e.quarantined_at = (long long)time(NULL);

    if (write_meta(meta_path, &e) != 0) {
        unlink(enc_path);
        unlink(meta_path);
        fprintf(stderr, "[!] Failed to write metadata for '%s'\n", filepath);
        return -1;
    }

    if (unlink(filepath) != 0) {
        fprintf(stderr,
                "[!] Vault entry %s saved but original '%s' could not be "
                "removed: %s\n", id, filepath, strerror(errno));
        return -1;
    }

    if (verbose)
        printf("[+] Quarantined: %s -> quarantine/%s.enc\n", filepath, id);
    return 0;
}

int quarantine_list(void) {
    DIR *d = opendir(QUARANTINE_DIR);
    if (!d) {
        printf("(quarantine is empty)\n");
        return 0;
    }

    printf("%-24s %12s  %-19s  %s\n",
           "ID", "SIZE", "QUARANTINED AT", "ORIGINAL PATH");
    printf("--------------------------------------------------------------------------------\n");

    struct dirent *entry;
    int count = 0;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        size_t nl = strlen(name);
        if (nl < 6 || strcmp(name + nl - 5, ".meta") != 0) continue;

        char path[1200];
        snprintf(path, sizeof(path), QUARANTINE_DIR "/%s", name);

        quarantine_entry e;
        if (parse_meta(path, &e) != 0) continue;

        char ts[32];
        time_t qt = (time_t)e.quarantined_at;
        struct tm tmb;
        localtime_r(&qt, &tmb);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmb);

        printf("%-24s %12lld  %-19s  %s\n",
               e.id, e.size, ts, e.original_path);
        count++;
    }
    closedir(d);

    printf("\n%d entr%s in vault.\n", count, count == 1 ? "y" : "ies");
    return 0;
}

int quarantine_restore(const char *id, const char *dest, int verbose) {
    if (!id || !id[0]) {
        fprintf(stderr, "[!] Missing quarantine ID\n");
        return -1;
    }

    if (ensure_quarantine_dir() != 0) return -1;

    char meta_path[1024];
    char enc_path[1024];
    snprintf(meta_path, sizeof(meta_path), QUARANTINE_DIR "/%s.meta", id);
    snprintf(enc_path,  sizeof(enc_path),  QUARANTINE_DIR "/%s.enc",  id);

    quarantine_entry e;
    if (parse_meta(meta_path, &e) != 0) {
        fprintf(stderr, "[!] No such quarantine entry: %s\n", id);
        return -1;
    }

    unsigned char key[KEY_LEN];
    if (load_or_create_key(key) != 0) return -1;

    FILE *in = fopen(enc_path, "rb");
    if (!in) {
        fprintf(stderr, "[!] Cannot open vault payload '%s'\n", enc_path);
        return -1;
    }

    const char *target = (dest && dest[0]) ? dest : e.original_path;
    if (!target[0]) {
        fclose(in);
        fprintf(stderr, "[!] No destination and no recorded original path\n");
        return -1;
    }

    struct stat st;
    if (stat(target, &st) == 0) {
        fclose(in);
        fprintf(stderr,
                "[!] Refusing to overwrite existing file: %s\n", target);
        return -1;
    }

    FILE *out = fopen(target, "wb");
    if (!out) {
        fclose(in);
        fprintf(stderr, "[!] Cannot create '%s': %s\n",
                target, strerror(errno));
        return -1;
    }

    char sha256[65];
    if (decrypt_stream(key, in, out, enc_path, sha256) != 0) {
        fclose(in);
        fclose(out);
        unlink(target);
        fprintf(stderr, "[!] Decryption/authentication failed for entry %s\n",
                id);
        return -1;
    }
    fclose(in);
    if (fclose(out) != 0) {
        unlink(target);
        fprintf(stderr, "[!] Failed to flush restored file\n");
        return -1;
    }

    if (strcmp(sha256, e.sha256) != 0) {
        unlink(target);
        fprintf(stderr,
                "[!] Integrity check failed for entry %s "
                "(SHA-256 mismatch)\n", id);
        return -1;
    }

    chmod(target, e.mode & 07777);

    struct timespec times[2];
    times[0].tv_sec = (time_t)e.mtime; times[0].tv_nsec = 0;
    times[1].tv_sec = (time_t)e.mtime; times[1].tv_nsec = 0;
    utimensat(AT_FDCWD, target, times, 0);

    unlink(meta_path);
    unlink(enc_path);

    if (verbose)
        printf("[+] Restored %s to %s\n", id, target);
    else
        printf("[+] Restored to %s\n", target);
    return 0;
}

int quarantine_clean(int older_than_days, int verbose) {
    if (older_than_days < 0) older_than_days = 0;

    DIR *d = opendir(QUARANTINE_DIR);
    if (!d) return 0;

    time_t now = time(NULL);
    time_t cutoff = now - (time_t)older_than_days * 86400;
    int remove_all = (older_than_days == 0);

    struct dirent *entry;
    int removed = 0;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        size_t nl = strlen(name);
        if (nl < 6 || strcmp(name + nl - 5, ".meta") != 0) continue;

        char meta_path[1200];
        snprintf(meta_path, sizeof(meta_path), QUARANTINE_DIR "/%s", name);

        quarantine_entry e;
        if (parse_meta(meta_path, &e) != 0) continue;

        if (!remove_all && e.quarantined_at >= cutoff) continue;

        char enc_path[1200];
        snprintf(enc_path, sizeof(enc_path), QUARANTINE_DIR "/%s.enc", e.id);

        unlink(enc_path);
        unlink(meta_path);
        removed++;

        if (verbose)
            printf("[+] Removed entry %s (%s)\n", e.id, e.original_path);
    }
    closedir(d);

    if (removed == 0)
        printf("[+] No entries to remove.\n");
    else
        printf("[+] Removed %d entr%s from vault.\n",
               removed, removed == 1 ? "y" : "ies");
    return 0;
}
