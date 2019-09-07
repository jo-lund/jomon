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

struct hashmap {
    struct hash_elem *table;
    hash_fn hash;
    hashmap_compare comp;
    hashmap_deallocate free_key;
    hashmap_deallocate free_data;
    unsigned int count;
    unsigned int buckets;
};

static inline unsigned int clp2(unsigned int x);
static void insert_elem(struct hash_elem *tbl, unsigned int size,
                        unsigned int hash_val, void *key, void *data);
static struct hash_elem *find_elem(hashmap_t *map, void *key);
static const hashmap_iterator *get_next_iterator(hashmap_t *map, unsigned int i);
static const hashmap_iterator *get_prev_iterator(hashmap_t *map, unsigned int i);

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

hashmap_t *hashmap_init(unsigned int size, hash_fn h, hashmap_compare fn)
{
    hashmap_t *map;

    map = malloc(sizeof(hashmap_t));
    map->buckets = clp2(size); /* set the size to a power of 2 */
    map->table = malloc(map->buckets * sizeof(struct hash_elem));
    for (unsigned int i = 0; i < map->buckets; i++) {
        map->table[i].hash_val = ~0;
    }
    map->hash = h ? h : default_hash;
    map->comp = fn ? fn : default_compare;
    map->free_key = NULL;
    map->free_data = NULL;
    map->count = 0;
    return map;
}

bool hashmap_insert(hashmap_t *map, void *key, void *data)
{
    /* do not allow duplicate keys */
    if (find_elem(map, key)) return false;

    /* resize the table if the load factor is greater than 0.5 */
    if ((map->count + 1) > map->buckets / 2) {
        struct hash_elem *tbl;
        unsigned int capacity;

        capacity = map->buckets * 2;
        tbl = malloc(capacity * sizeof(struct hash_elem));
        for (unsigned int i = 0; i < capacity; i++) {
            tbl[i].hash_val = ~0;
        }
        for (unsigned int j = 0; j < map->buckets; j++) {
            if (map->table[j].hash_val != (unsigned int) ~0) {
                insert_elem(tbl, capacity, map->table[j].hash_val,
                            map->table[j].key, map->table[j].data);
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

void hashmap_remove(hashmap_t *map, void *key)
{
    struct hash_elem *elem = NULL;
    unsigned int i = map->hash(key) & (map->buckets - 1);
    unsigned int j = 0;

    while (map->table[i].hash_val != (unsigned int) ~0 && j < map->buckets) {
        if (map->comp(map->table[i].key, key) == 0) {
            elem = &map->table[i];
            break;
        }
        i = (i + 1) & (map->buckets - 1);
        j++;
    }
    if (elem) {
        if (map->free_key) {
            map->free_key(elem->key);
        }
        if (map->free_data) {
            map->free_data(elem->data);
        }
        elem->hash_val = ~0;
        map->count--;
        i = (i + 1) & (map->buckets - 1);
        j++;

        /* re-insert every item after 'i' until we encounter a free slot */
        while (map->table[i].hash_val != (unsigned int) ~0 && j < map->buckets) {
            unsigned int hash = map->table[i].hash_val;

            map->table[i].hash_val = ~0;
            insert_elem(map->table, map->buckets, hash, map->table[i].key,
                        map->table[i].data);
            i = (i + 1) & (map->buckets - 1);
            j++;
        }
    }
}

void *hashmap_get(hashmap_t *map, void *key)
{
    struct hash_elem *elem = find_elem(map, key);

    if (elem) return elem->data;
    return NULL;
}

bool hashmap_contains(hashmap_t *map, void *key)
{
    return find_elem(map, key);
}

unsigned int hashmap_size(hashmap_t *map)
{
    return map->count;
}

const hashmap_iterator *hashmap_first(hashmap_t *map)
{
    return get_next_iterator(map, 0);
}

const hashmap_iterator *hashmap_next(hashmap_t *map, const hashmap_iterator *it)
{
    struct hash_elem *elem = (struct hash_elem *) it;
    unsigned int idx = (elem->hash_val + elem->probe_count + 1) & (map->buckets - 1);

    if (idx == 0) {
        return NULL;
    }
    return get_next_iterator(map, idx);
}

const hashmap_iterator *hashmap_prev(hashmap_t *map, const hashmap_iterator *it)
{
    struct hash_elem *elem = (struct hash_elem *) it;
    unsigned int idx = (elem->hash_val + elem->probe_count - 1) & (map->buckets - 1);

    if (idx <= 0) {
        return NULL;
    }
    return get_prev_iterator(map, idx);
}

const hashmap_iterator *hashmap_get_it(hashmap_t *map, void *key)
{
    struct hash_elem *elem = find_elem(map, key);

    if (elem) {
        return (const hashmap_iterator *) elem;
    }
    return NULL;
}

void hashmap_clear(hashmap_t *map)
{
    for (unsigned int i = 0; i < map->buckets; i++) {
        if (map->table[i].hash_val != (unsigned int) ~0) {
            if (map->free_key) {
                map->free_key(map->table[i].key);
            }
            if (map->free_data) {
                map->free_data(map->table[i].data);
            }
            map->table[i].hash_val = ~0;
        }
    }
    map->count = 0;
}

void hashmap_set_free_key(hashmap_t *map, hashmap_deallocate fn)
{
    map->free_key = fn;
}

void hashmap_set_free_data(hashmap_t *map, hashmap_deallocate fn)
{
    map->free_data = fn;
}

void hashmap_free(hashmap_t *map)
{
    for (unsigned int i = 0; i < map->buckets; i++) {
        if (map->table[i].hash_val != (unsigned int) ~0) {
            if (map->free_key) {
                map->free_key(map->table[i].key);
            }
            if (map->free_data) {
                map->free_data(map->table[i].data);
            }
        }
    }
    free(map->table);
    free(map);
}

struct hash_elem *find_elem(hashmap_t *map, void *key)
{
    unsigned int i = map->hash(key) & (map->buckets - 1);
    unsigned int j = 0;

    while (map->table[i].hash_val != (unsigned int) ~0 && j < map->buckets) {
        if (map->comp(map->table[i].key, key) == 0) {
            return &map->table[i];
        }
        i = (i + 1) & (map->buckets - 1);
        j++;
    }
    return NULL;
}

void insert_elem(struct hash_elem *tbl, unsigned int size, unsigned int hash_val,
                 void *key, void *data)
{
    unsigned int i = hash_val & (size - 1);
    unsigned int pc = 0;

    /* use linear probing to find an empty bucket */
    while (tbl[i].hash_val != (unsigned int) ~0) {
        i = (i + 1) & (size - 1);
        pc++;
    }
    tbl[i].key = key;
    tbl[i].data = data;
    tbl[i].hash_val = hash_val;
    tbl[i].probe_count = pc;
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

const hashmap_iterator *get_next_iterator(hashmap_t *map, unsigned int i)
{
    while (map->table[i].hash_val == (unsigned int) ~0) {
        if (++i >= map->buckets) {
            return NULL;
        }
    }
    return (const hashmap_iterator *) &map->table[i];
}

const hashmap_iterator *get_prev_iterator(hashmap_t *map, unsigned int i)
{
    while (map->table[i].hash_val == (unsigned int) ~0) {
        if (--i <= 0) {
            return NULL;
        }
    }
    return (const hashmap_iterator *) &map->table[i];
}

hashmap_stat_t hashmap_get_stat(hashmap_t *map)
{
    hashmap_stat_t stat;
    unsigned int pcc = 0;

    stat.lpc = 0;
    for (unsigned int i = 0; i < map->buckets; i++) {
        if (map->table[i].hash_val != (unsigned int) ~0) {
            if (stat.lpc < map->table[i].probe_count) {
                stat.lpc = map->table[i].probe_count;
            }
            pcc += map->table[i].probe_count;
        }
    }
    stat.avgpc = (double) pcc / map->count;
    stat.load = (double) map->count / map->buckets;
    return stat;
}
