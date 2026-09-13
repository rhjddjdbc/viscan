ifndef QUARANTINE_H
#define QUARANTINE_H

typedef struct {
    char id[64];
    char original_path[4096];
    char md5[33];
    char sha256[65];
    long long size;
    unsigned int mode;
    long long mtime;
    int uid;
    int gid;
    long long quarantined_at;
    char reason[256];
} quarantine_entry;

/*
 * Move a file into the encrypted quarantine vault.
 * Returns 0 on success, -1 on failure.
 */
int quarantine_file(const char *filepath, const char *md5,
                    const char *reason, int verbose);

/* Print all vault entries. Returns 0 on success. */
int quarantine_list(void);

/*
 * Restore an entry to `dest` (or to its original path if `dest` is NULL).
 * Fails if the destination already exists.
 * Returns 0 on success, -1 on failure.
 */
int quarantine_restore(const char *id, const char *dest, int verbose);

/*
 * Delete entries older than `older_than_days` days.
 * Pass 0 to remove everything.
 */
int quarantine_clean(int older_than_days, int verbose);

#endif /* QUARANTINE_H */
