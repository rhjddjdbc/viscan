#ifndef AC_ENGINE_H
#define AC_ENGINE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Minimal Aho-Corasick multi-pattern matcher.
 *
 * - Patterns are added with a user-chosen int32 id.
 * - The id is returned in the match callback.
 * - Patterns must be added before ac_build().
 * - ac_search() runs the automaton in a single pass over the haystack.
 */

typedef struct ac_engine ac_engine;

ac_engine *ac_create(void);
void       ac_destroy(ac_engine *e);

/* Returns 0 on success, -1 on error. */
int  ac_add(ac_engine *e, const uint8_t *pattern, size_t len, int32_t id);

/* Must be called after all ac_add() and before ac_search(). */
int  ac_build(ac_engine *e);

/*
 * Callback for each match.
 *   id       : the id passed to ac_add()
 *   end_pos  : exclusive end position of the match in the haystack
 *   user     : opaque pointer from ac_search()
 * Return non-zero to stop the search early; that value is returned
 * by ac_search().
 */
typedef int (*ac_match_fn)(int32_t id, size_t end_pos, void *user);

/* Returns 0 if the search completed normally, or the callback's
 * non-zero return value if it stopped early. */
int  ac_search(ac_engine *e, const uint8_t *haystack, size_t len,
               ac_match_fn cb, void *user);

#endif /* AC_ENGINE_H */
