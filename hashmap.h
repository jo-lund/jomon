#ifndef HASH_MAP_H
#define HASH_MAP_H

#include <stdbool.h>

typedef struct hash_map hash_map_t;
typedef void (*hash_map_deallocate)(void *);

/* User defined hash function */
typedef unsigned int (*hash_fn)(const void *key);

/*
 * User defined comparison function. It must return an integer less than, equal
 * to, or greater than zero if the first argument is considered to be
 * respectively less than, equal to, or greater than the second.
 */
typedef int (*hash_map_compare)(const void *, const void *);

typedef struct hash_map_iterator {
    void *key;
    void *data;
} hash_map_iterator;

/* Initializes hash map */
hash_map_t *hash_map_init(unsigned int size, hash_fn h, hash_map_compare fn);

/* Inserts element with specified key in hash map */
bool hash_map_insert(hash_map_t *map, void *key, void *data);

/* Removes element with specified key */
void hash_map_remove(hash_map_t *map, void *key);

/* Returns element with the specified key */
void *hash_map_get(hash_map_t *map, void *key);

/* Returns the number of elements in the hash map */
unsigned int hash_map_size(hash_map_t *map);

/* Returns an iterator to the beginning of the hash map */
const hash_map_iterator *hash_map_first(hash_map_t *map);

/* Returns the next iterator */
const hash_map_iterator *hash_map_next(hash_map_t *map, const hash_map_iterator *it);

/* Returns the iterator with the specified key */
const hash_map_iterator *hash_map_get_it(hash_map_t *map, void *key);

/* Clears the content of the hash map */
void hash_map_clear(hash_map_t *map);

/* Frees all memory used by hash map */
void hash_map_free(hash_map_t *map);

/*
 * If the key should be deallocated, this sets the function that will free the
 * key. The key will be freed on removal and when calling hash_map_free.
 */
void hash_map_set_free_key(hash_map_t *map, hash_map_deallocate fn);

/*
 * If the data should be deallocated, this sets the function that will free the
 * data. The data will be freed on removal and when calling hash_map_free.
 */
void hash_map_set_free_data(hash_map_t *map, hash_map_deallocate fn);

#endif
