#ifndef HASH_H
#define HASH_H

#include <stdint.h>
#include <string.h>
#include "util.h"

static inline unsigned int hashdjb_string(const void *key)
{
   unsigned int hash = 5381;
   char *val = (char *) key;

   while (*val != '\0') {
       hash = ((hash << 5) + hash) + *val++;
   }
   return hash;
}

static inline unsigned int hashfnv_string(const void *key)
{
    unsigned int hash = 2166136261;
    char *val = (char *) key;

    while (*val != '\0')
        hash = (hash ^ *val++) * 16777619;
    return hash;
}

static inline int compare_string(const void *e1, const void *e2)
{
    return strcmp((char *) e1, (char *) e2);
}

static inline unsigned int hashdjb_uint16(const void *key)
{
   unsigned int hash = 5381;
   uint16_t val = PTR_TO_UINT(key);

   for (unsigned int i = 0; i < 2; i++) {
       hash = ((hash << 5) + hash) + ((val >> (i * 8)) & 0xff);
   }
   return hash;
}

static inline unsigned int hashdjb_uint32(const void *key)
{
   unsigned int hash = 5381;
   uint32_t val = PTR_TO_UINT(key);

   for (unsigned int i = 0; i < 4; i++) {
       hash = ((hash << 5) + hash) + ((val >> (i * 8)) & 0xff);
   }
   return hash;
}

static inline unsigned int hashfnv_uint16(const void *key)
{
    unsigned int hash = 2166136261;
    uint16_t val = PTR_TO_UINT(key);

    for (int i = 0; i < 2; i++)
        hash = (hash ^ ((val >> (8 * i)) & 0xff)) * 16777619;
    return hash;
}

static inline unsigned int hashfnv_uint32(const void *key)
{
    unsigned int hash = 2166136261;
    uint32_t val = PTR_TO_UINT(key);

    for (int i = 0; i < 4; i++)
        hash = (hash ^ ((val >> (8 * i)) & 0xff)) * 16777619;
    return hash;
}

static inline unsigned int hashfnv_uint64(const void *key)
{
    uint64_t hash = 14695981039346656037U;
    uint64_t val = PTR_TO_UINT(key);

    for (int i = 0; i < 8; i++)
        hash = (hash ^ ((val >> (8 * i)) & 0xff)) * 1099511628211;
    return hash;
}

static inline int compare_uint(const void *e1, const void *e2)
{
    return PTR_TO_UINT(e1) - PTR_TO_UINT(e2);
}

#endif
