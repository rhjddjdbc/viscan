#ifndef HDB_PARSER_H
#define HDB_PARSER_H

void set_verbose(int v);
void load_signatures_from_database(void);
int hash_in_signatures(const char *hash);
void free_signatures(void);

#endif // HDB_PARSER_H

