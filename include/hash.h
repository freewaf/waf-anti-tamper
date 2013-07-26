/* Copyright (C) 2001-2003 IP Infusion, Inc. All Rights Reserved. */

#ifndef _LIB_HASH_H_
#define _LIB_HASH_H_

/* Default hash table size.  */
#define HASHTABSIZE     10240

typedef struct hash
{
    /* Hash backet. */
    struct hash_backet **index;

    /* Hash table size. */
    unsigned int size;

    /* Key make function. */
    unsigned int (*hash_key)(char *);

    /* Data compare function. */
    int (*hash_cmp)(void *, void *);

    /* Backet alloc. */
    unsigned int count;
} hash_t;

extern unsigned int hash_key_fun(char *hash_key);
extern struct hash *hash_create(unsigned int (*hash_key)(char *), int (*hash_cmp)(void *, void *));
extern void *hash_set(struct hash *hash, char *hash_key, void *hash_value);
extern void *hash_get(struct hash *hash, char *hash_key);
extern void hash_clean(struct hash *hash, void (*free_func)(void *));
extern void hash_destroy(struct hash *hash, void (*free_func)(void *));
extern void hash_delete_node(struct hash *hash, void (*free_func)(void *), 
                int (*hash_cmp)(void *, void *), void *data);

#endif /* _LIB_HASH_H_ */

