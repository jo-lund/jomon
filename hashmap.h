#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdbool.h>

#define HASHMAP_FOREACH(m, i) \
    for ((i) = hashmap_first(m); (i); (i) = hashmap_next(m, (i)))

typedef struct hashmap hashmap_t;
typedef void (*hashmap_deallocate)(void *);

/* User defined hash function */
typedef unsigned int (*hash_fn)(const void *key);

/*
 * User defined comparison function. It must return an integer less than, equal
 * to, or greater than zero if the first argument is considered to be
 * respectively less than, equal to, or greater than the second.
 */
typedef int (*hashmap_compare)(const void *, const void *);

typedef struct hashmap_iterator {
    void *key;
    void *data;
} hashmap_iterator;

typedef struct hashmap_stat {
    unsigned int lpc; /* longest probe count */
    double avgpc;     /* average probe count */
    double load;      /* load factor */
} hashmap_stat_t;

/*
 * Initializes hash map. If the hash function and/or compare function are NULL,
 * default functions that assume the key can be used as a uint32_t are used.
 */
hashmap_t *hashmap_init(unsigned int size, hash_fn h, hashmap_compare fn);

/*
 * Inserts element with specified key in hash map. Returns true if the element
 * is inserted or false if the element is updated.
 */
bool hashmap_insert(hashmap_t *map, void *key, void *data);

/* Removes element with specified key */
void hashmap_remove(hashmap_t *map, void *key);

/* Returns element with the specified key */
void *hashmap_get(hashmap_t *map, void *key);

/* Returns the key stored in the hash table */
void *hashmap_get_key(hashmap_t *map, void *key);

/* Returns whether the hashmap contains an element with the specified key */
bool hashmap_contains(hashmap_t *map, void *key);

/* Returns the number of elements in the hash map */
unsigned int hashmap_size(hashmap_t *map);

/* Returns an iterator to the beginning of the hash map */
const hashmap_iterator *hashmap_first(hashmap_t *map);

/* Returns the next iterator */
const hashmap_iterator *hashmap_next(hashmap_t *map, const hashmap_iterator *it);

/* Returns the previous iterator */
const hashmap_iterator *hashmap_prev(hashmap_t *map, const hashmap_iterator *it);

/* Returns the iterator with the specified key */
const hashmap_iterator *hashmap_get_it(hashmap_t *map, void *key);

/* Clears the content of the hash map */
void hashmap_clear(hashmap_t *map);

/* Frees all memory used by hash map */
void hashmap_free(hashmap_t *map);

/*
 * If the key should be deallocated, this sets the function that will free the
 * key. The key will be freed on removal and when calling hashmap_free.
 */
void hashmap_set_free_key(hashmap_t *map, hashmap_deallocate fn);

/*
 * If the data should be deallocated, this sets the function that will free the
 * data. The data will be freed on removal and when calling hashmap_free.
 */
void hashmap_set_free_data(hashmap_t *map, hashmap_deallocate fn);

/* Get hash map statistics */
hashmap_stat_t hashmap_get_stat(hashmap_t *map);

#endif
