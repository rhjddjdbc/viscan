#include "ac_engine.h"

#include <stdlib.h>
#include <string.h>

#define AC_ROOT 0

/* -------------------------------------------------------------- */
/* Internal data structures                                        */
/* -------------------------------------------------------------- */

typedef struct {
    int32_t fail;
    int32_t first_edge;
    int32_t first_output;
    int32_t output_link;   /* nearest fail-ancestor that has own outputs */
} ac_node;

typedef struct {
    uint8_t ch;
    int32_t child;
    int32_t next;          /* next edge for the same node */
} ac_edge;

typedef struct {
    int32_t id;
    int32_t next;          /* next output for the same node */
} ac_output;

struct ac_engine {
    ac_node   *nodes;
    int32_t    node_count;
    int32_t    node_cap;

    ac_edge   *edges;
    int32_t    edge_count;
    int32_t    edge_cap;

    ac_output *outputs;
    int32_t    output_count;
    int32_t    output_cap;

    int32_t   *queue;
    int32_t    queue_cap;

    int32_t    root_next[256];  /* fast path for root transitions */

    int        built;
};

/* -------------------------------------------------------------- */
/* Growable arrays                                                 */
/* -------------------------------------------------------------- */

static int32_t new_node(ac_engine *e) {
    if (e->node_count == e->node_cap) {
        int32_t nc = e->node_cap ? e->node_cap * 2 : 1024;
        ac_node *p = realloc(e->nodes, (size_t)nc * sizeof(*p));
        if (!p) return -1;
        e->nodes = p;
        e->node_cap = nc;
    }
    ac_node *n = &e->nodes[e->node_count];
    n->fail         = -1;
    n->first_edge   = -1;
    n->first_output = -1;
    n->output_link  = -1;
    return e->node_count++;
}

static int add_edge(ac_engine *e, int32_t node, uint8_t ch, int32_t child) {
    if (e->edge_count == e->edge_cap) {
        int32_t nc = e->edge_cap ? e->edge_cap * 2 : 4096;
        ac_edge *p = realloc(e->edges, (size_t)nc * sizeof(*p));
        if (!p) return -1;
        e->edges = p;
        e->edge_cap = nc;
    }
    int32_t idx = e->edge_count++;
    e->edges[idx].ch     = ch;
    e->edges[idx].child  = child;
    e->edges[idx].next   = e->nodes[node].first_edge;
    e->nodes[node].first_edge = idx;
    return 0;
}

static int add_output(ac_engine *e, int32_t node, int32_t id) {
    if (e->output_count == e->output_cap) {
        int32_t nc = e->output_cap ? e->output_cap * 2 : 4096;
        ac_output *p = realloc(e->outputs, (size_t)nc * sizeof(*p));
        if (!p) return -1;
        e->outputs = p;
        e->output_cap = nc;
    }
    int32_t idx = e->output_count++;
    e->outputs[idx].id   = id;
    e->outputs[idx].next = e->nodes[node].first_output;
    e->nodes[node].first_output = idx;
    return 0;
}

/* -------------------------------------------------------------- */
/* Edge lookup (sparse linear scan)                                */
/* -------------------------------------------------------------- */

static int32_t find_edge(const ac_engine *e, int32_t node, uint8_t ch) {
    for (int32_t i = e->nodes[node].first_edge; i != -1; i = e->edges[i].next) {
        if (e->edges[i].ch == ch) return e->edges[i].child;
    }
    return -1;
}

/* -------------------------------------------------------------- */
/* Public API                                                      */
/* -------------------------------------------------------------- */

ac_engine *ac_create(void) {
    ac_engine *e = calloc(1, sizeof(*e));
    if (!e) return NULL;
    for (int i = 0; i < 256; i++) e->root_next[i] = -1;
    if (new_node(e) < 0) { free(e); return NULL; }
    return e;
}

void ac_destroy(ac_engine *e) {
    if (!e) return;
    free(e->nodes);
    free(e->edges);
    free(e->outputs);
    free(e->queue);
    free(e);
}

int ac_add(ac_engine *e, const uint8_t *pattern, size_t len, int32_t id) {
    if (!e || !pattern || len == 0 || e->built) return -1;
    int32_t cur = AC_ROOT;
    for (size_t i = 0; i < len; i++) {
        int32_t next = find_edge(e, cur, pattern[i]);
        if (next < 0) {
            next = new_node(e);
            if (next < 0) return -1;
            if (add_edge(e, cur, pattern[i], next) != 0) return -1;
        }
        cur = next;
    }
    return add_output(e, cur, id);
}

int ac_build(ac_engine *e) {
    if (!e || e->built) return -1;
    e->built = 1;

    if (e->node_count == 0) return 0;
    e->queue_cap = e->node_count;
    e->queue = malloc((size_t)e->queue_cap * sizeof(int32_t));
    if (!e->queue) return -1;

    int32_t head = 0, tail = 0;

    /* Root's children: fail = root, and seed root_next[]. */
    for (int32_t i = e->nodes[AC_ROOT].first_edge; i != -1; i = e->edges[i].next) {
        int32_t child = e->edges[i].child;
        e->nodes[child].fail = AC_ROOT;
        e->queue[tail++] = child;
        e->root_next[e->edges[i].ch] = child;
    }

    /* BFS to compute fail links. */
    while (head < tail) {
        int32_t u = e->queue[head++];
        for (int32_t i = e->nodes[u].first_edge; i != -1; i = e->edges[i].next) {
            uint8_t ch = e->edges[i].ch;
            int32_t v  = e->edges[i].child;

            int32_t f  = e->nodes[u].fail;
            int32_t fc = -1;
            while (f != AC_ROOT) {
                fc = find_edge(e, f, ch);
                if (fc >= 0) break;
                f = e->nodes[f].fail;
            }
            if (fc < 0) fc = find_edge(e, AC_ROOT, ch);

            if (fc >= 0 && fc != v) e->nodes[v].fail = fc;
            else                      e->nodes[v].fail = AC_ROOT;

            e->queue[tail++] = v;
        }
    }

    /* Output links: nearest fail-ancestor with own outputs. */
    for (int32_t i = 0; i < e->node_count; i++) {
        if (i == AC_ROOT) { e->nodes[i].output_link = -1; continue; }
        int32_t f = e->nodes[i].fail;
        if (f < 0 || f == AC_ROOT) {
            e->nodes[i].output_link = -1;
        } else if (e->nodes[f].first_output != -1) {
            e->nodes[i].output_link = f;
        } else {
            e->nodes[i].output_link = e->nodes[f].output_link;
        }
    }
    return 0;
}

int ac_search(ac_engine *e, const uint8_t *haystack, size_t len,
              ac_match_fn cb, void *user) {
    if (!e || !e->built || !cb || !haystack) return 0;

    int32_t s = AC_ROOT;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = haystack[i];

        int32_t next = -1;
        while (s != AC_ROOT) {
            next = find_edge(e, s, c);
            if (next >= 0) break;
            s = e->nodes[s].fail;
        }
        if (next < 0) next = e->root_next[c];
        s = (next >= 0) ? next : AC_ROOT;

        for (int32_t n = s; n != -1; n = e->nodes[n].output_link) {
            for (int32_t o = e->nodes[n].first_output; o != -1; o = e->outputs[o].next) {
                int r = cb(e->outputs[o].id, i + 1, user);
                if (r != 0) return r;
            }
        }
    }
    return 0;
}
