#include "hashmap.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct hash_elem {
    void *key;
    void *data;
    unsigned int hash_val;
    unsigned int probe_count;
};

struct hash_map {
    struct hash_elem **table;
    hash_fn hash;
    hash_map_compare comp;
    hash_map_deallocate free_key;
    hash_map_deallocate free_data;
    unsigned int count;
    unsigned int buckets;
};

static inline unsigned int clp2(unsigned int x);
static void insert_elem(struct hash_elem **tbl, unsigned int size,
                        unsigned int hash_val, void *key, void *data);
static struct hash_elem *find_elem(hash_map_t *map, void *key);
static const hash_map_iterator *get_next_iterator(hash_map_t *map, unsigned int i);
static const hash_map_iterator *get_prev_iterator(hash_map_t *map, unsigned int i);

static inline unsigned int default_hash(const void *key)
{
    unsigned int hash = 2166136261;
    uint32_t val = *(uint32_t *) key;

    for (int i = 0; i < 4; i++) {
        hash = (hash ^ ((val >> (8 * i)) & 0xff)) * 16777619;
    }
    return hash;
}

static inline int default_compare(const void *e1, const void *e2)
{
    return *(uint32_t *) e1 - *(uint32_t *) e2;
}

hash_map_t *hash_map_init(unsigned int size, hash_fn h, hash_map_compare fn)
{
    hash_map_t *map;

    map = malloc(sizeof(hash_map_t));
    map->buckets = clp2(size); /* set the size to a power of 2 */
    map->table = calloc(map->buckets, sizeof(struct hash_elem *));
    map->hash = h ? h : default_hash;
    map->comp = fn ? fn : default_compare;
    map->free_key = NULL;
    map->free_data = NULL;
    map->count = 0;
    return map;
}

bool hash_map_insert(hash_map_t *map, void *key, void *data)
{
    /* do not allow duplicate keys */
    if (find_elem(map, key)) return false;

    /* resize the table if the load factor is greater than 0.5 */
    if ((map->count + 1) > map->buckets / 2) {
        struct hash_elem **tbl;
        unsigned int capacity;

        capacity = map->buckets * 2;
        tbl = calloc(capacity, sizeof(struct hash_elem *));
        for (unsigned int j = 0; j < map->buckets; j++) {
            if (map->table[j] != NULL &&
                map->table[j]->hash_val != (unsigned int) ~0) {
                insert_elem(tbl, capacity, map->table[j]->hash_val,
                            map->table[j]->key, map->table[j]->data);
            }
        }
        map->buckets = capacity;
        free(map->table);
        map->table = tbl;
    }
    insert_elem(map->table, map->buckets, map->hash(key), key, data);
    map->count++;
    return true;
}

void hash_map_remove(hash_map_t *map, void *key)
{
    struct hash_elem *elem = find_elem(map, key);

    if (elem) {
        if (map->free_key) {
            map->free_key(elem->key);
        }
        if (map->free_data) {
            map->free_data(elem->data);
        }
        elem->hash_val = ~0;
        map->count--;
    }
}

void *hash_map_get(hash_map_t *map, void *key)
{
    struct hash_elem *elem = find_elem(map, key);

    if (elem) return elem->data;
    return NULL;
}

bool hash_map_contains(hash_map_t *map, void *key)
{
    return find_elem(map, key);
}

unsigned int hash_map_size(hash_map_t *map)
{
    return map->count;
}

const hash_map_iterator *hash_map_first(hash_map_t *map)
{
    return get_next_iterator(map, 0);
}

const hash_map_iterator *hash_map_next(hash_map_t *map, const hash_map_iterator *it)
{
    struct hash_elem *elem = (struct hash_elem *) it;
    unsigned int idx = (elem->hash_val + elem->probe_count + 1) & (map->buckets - 1);

    if (idx == 0) {
        return NULL;
    }
    return get_next_iterator(map, idx);
}

const hash_map_iterator *hash_map_prev(hash_map_t *map, const hash_map_iterator *it)
{
    struct hash_elem *elem = (struct hash_elem *) it;
    unsigned int idx = (elem->hash_val + elem->probe_count - 1) & (map->buckets - 1);

    if (idx <= 0) {
        return NULL;
    }
    return get_prev_iterator(map, idx);
}

const hash_map_iterator *hash_map_get_it(hash_map_t *map, void *key)
{
    struct hash_elem *elem = find_elem(map, key);

    if (elem) {
        return (const hash_map_iterator *) elem;
    }
    return NULL;
}

void hash_map_clear(hash_map_t *map)
{
    for (unsigned int i = 0; i < map->buckets; i++) {
        if (map->table[i] != NULL && map->table[i]->hash_val != (unsigned int) ~0) {
            if (map->free_key) {
                map->free_key(map->table[i]->key);
            }
            if (map->free_data) {
                map->free_data(map->table[i]->data);
            }
            map->table[i]->hash_val = ~0;
        }
    }
    map->count = 0;
}

void hash_map_set_free_key(hash_map_t *map, hash_map_deallocate fn)
{
    map->free_key = fn;
}

void hash_map_set_free_data(hash_map_t *map, hash_map_deallocate fn)
{
    map->free_data = fn;
}

void hash_map_free(hash_map_t *map)
{
    for (unsigned int i = 0; i < map->buckets; i++) {
        if (map->table[i] != NULL) {
            if (map->table[i]->hash_val != (unsigned int) ~0) {
                if (map->free_key) {
                    map->free_key(map->table[i]->key);
                }
                if (map->free_data) {
                    map->free_data(map->table[i]->data);
                }
            }
            free(map->table[i]);
        }
    }
    free(map->table);
    free(map);
}

struct hash_elem *find_elem(hash_map_t *map, void *key)
{
    unsigned int i = map->hash(key) & (map->buckets - 1);
    unsigned int j = 0;

    while (map->table[i] != NULL && map->table[i]->hash_val != (unsigned int) ~0
           && j < map->buckets) {
        if (map->comp(map->table[i]->key, key) == 0) {
            return map->table[i];
        }
        i = (i + 1) & (map->buckets - 1);
        j++;
    }
    return NULL;
}

void insert_elem(struct hash_elem **tbl, unsigned int size, unsigned int hash_val,
                 void *key, void *data)
{
    unsigned int i = hash_val & (size - 1);
    unsigned int pc = 0;

    /* use linear probing to find an empty bucket */
    while (tbl[i] != NULL && tbl[i]->hash_val != (unsigned int) ~0) {
        i = (i + 1) & (size - 1);
        pc++;
    }
    if (!tbl[i]) {
        tbl[i] = malloc(sizeof(struct hash_elem));
    }
    tbl[i]->key = key;
    tbl[i]->data = data;
    tbl[i]->hash_val = hash_val;
    tbl[i]->probe_count = pc;
}

/* Computes the least power of two greater than or equal to x */
inline unsigned int clp2(unsigned int x)
{
    x--;
    x = x | (x >> 1);
    x = x | (x >> 2);
    x = x | (x >> 4);
    x = x | (x >> 8);
    x = x | (x >> 16);
    return x + 1;
}

const hash_map_iterator *get_next_iterator(hash_map_t *map, unsigned int i)
{
    while (map->table[i] == NULL ||
           map->table[i]->hash_val == (unsigned int) ~0) {
        if (++i >= map->buckets) {
            return NULL;
        }
    }
    return (const hash_map_iterator *) map->table[i];
}

const hash_map_iterator *get_prev_iterator(hash_map_t *map, unsigned int i)
{
    while (map->table[i] == NULL ||
           map->table[i]->hash_val == (unsigned int) ~0) {
        if (--i <= 0) {
            return NULL;
        }
    }
    return (const hash_map_iterator *) map->table[i];
}

hash_map_stat_t hash_map_get_stat(hash_map_t *map)
{
    hash_map_stat_t stat;
    unsigned int pcc = 0;

    stat.lpc = 0;
    for (unsigned int i = 0; i < map->buckets; i++) {
        if (map->table[i] != NULL && map->table[i]->hash_val != (unsigned int) ~0) {
            if (stat.lpc < map->table[i]->probe_count) {
                stat.lpc = map->table[i]->probe_count;
            }
            pcc += map->table[i]->probe_count;
        }
    }
    stat.avgpc = (double) pcc / map->count;
    stat.load = (double) map->count / map->buckets;
    return stat;
}
