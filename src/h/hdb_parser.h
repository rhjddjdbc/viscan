#ifndef HDB_PARSER_H
#define HDB_PARSER_H

void set_verbose(int v);

/*
 * Enable best-effort pattern matching against .ndb signatures.
 * Disabled by default — the naive matcher produces many false
 * positives on untrusted binary input.
 */
void set_pattern_scan(int enabled);

int  load_signatures_from_database(void);
int  hash_in_signatures(const char *hash);
int  file_has_pattern_match(const char *path);
void free_signatures(void);

#endif /* HDB_PARSER_H */
