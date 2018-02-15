#include "hashmap.h"
#include <stdlib.h>
#include <string.h>

struct hash_elem {
    unsigned int hash_val;
    unsigned int probe_count;
    void *key;
    void *data;
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
                        unsigned int i, void *key, void *data);
static struct hash_elem *find_elem(hash_map_t *map, void *key);

hash_map_t *hash_map_init(unsigned int size, hash_fn h, hash_map_compare fn)
{
    hash_map_t *map;

    map = malloc(sizeof(hash_map_t));
    map->buckets = clp2(size); /* set the size to a power of 2 */
    map->table = calloc(map->buckets, sizeof(struct hash_elem *));
    map->hash = h;
    map->comp = fn;
    map->free_key = NULL;
    map->free_data = NULL;
    map->count = 0;
    return map;
}

bool hash_map_insert(hash_map_t *map, void *key, void *data)
{
    unsigned int i;

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
    i = map->hash(key) & (map->buckets - 1);
    insert_elem(map->table, map->buckets, i, key, data);
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

void insert_elem(struct hash_elem **tbl, unsigned int size, unsigned int i,
                 void *key, void *data)
{
    /* use linear probing to find an empty bucket */
    while (tbl[i] != NULL && tbl[i]->hash_val != (unsigned int) ~0) {
        i = (i + 1) & (size - 1);
    }
    tbl[i] = malloc(sizeof(struct hash_elem));
    tbl[i]->key = key;
    tbl[i]->data = data;
    tbl[i]->hash_val = i;
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
