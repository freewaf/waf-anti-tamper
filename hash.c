/* Copyright (C) 2001-2003 IP Infusion, Inc. All Rights Reserved. */

#include <stdlib.h>
#include <string.h>
#include "hash.h"

struct hash_backet
{
    /* Linked list.  */
    struct hash_backet *next;

    /* Hash key. */
    unsigned int key;

    /* Data.  */
    void *data;
};

/* Allocate a new hash.  */
struct hash *lib_hash_create_size(unsigned int size, unsigned int (*hash_key)(char *),
                                  int (*hash_cmp)(void *, void *))
{
    struct hash *hash;

    hash = malloc(sizeof(struct hash));
    if (hash == NULL) {
        return NULL;
    }

    hash->index = malloc(sizeof(struct hash_backet *) * size);
    if (hash->index == NULL) {
        free(hash);
        return NULL;
    }

    memset(hash->index, 0, sizeof(struct hash_backet *) * size);
    hash->size = size;
    hash->hash_key = hash_key;
    hash->hash_cmp = hash_cmp;
    hash->count = 0;

    return hash;
}

/* Allocate a new hash with default hash size.  */
struct hash *lib_hash_create(unsigned int (*hash_key)(char *), int (*hash_cmp)(void *, void *))
{
    return lib_hash_create_size(HASHTABSIZE, hash_key, hash_cmp);
}

/* Utility function for hash_get().  When this function is specified
   as alloc_func, return arugment as it is.  This function is used for
   intern already allocated value.  */
void *lib_hash_alloc_intern(void *arg)
{
    return arg;
}

/* Lookup and return hash backet in hash.  If there is no
   corresponding hash backet and alloc_func is specified, create new
   hash backet.  */
void *lib_hash_get(struct hash *hash, void *data, void * (*alloc_func)(void *))
{
    unsigned int key;
    unsigned int index;
    void *newdata;
    struct hash_backet *backet;

    key = (*hash->hash_key)(data);
    index = key % hash->size;

    for (backet = hash->index[index]; backet != NULL; backet = backet->next) {
        if (backet->key == key && (*hash->hash_cmp)(backet->data, data)) {
            return backet->data;
        }
    }

    if (alloc_func) {
        newdata = (*alloc_func)(data);
        if (newdata == NULL) {
            return NULL;
        }

        backet = malloc(sizeof(struct hash_backet));
        if (backet == NULL) {
            return NULL;
        }
        backet->data = newdata;
        backet->key = key;
        backet->next = hash->index[index];
        hash->index[index] = backet;
        hash->count++;
        return backet->data;
    }
    return NULL;
}

/* XXX:chenshaohong@ruijie.com.cn add new backet, the new backet nust be not exist */
void *lib_hash_add(struct hash *hash, void *newdata)
{
    unsigned int key;
    unsigned int index;
    struct hash_backet *backet;

    if (hash == NULL || newdata == NULL) {
        return NULL;
    }

    key = (*hash->hash_key)(newdata);
    index = key % hash->size;

    backet = malloc(sizeof (struct hash_backet));
    if (backet == NULL) {
        return NULL;
    }
    backet->data = newdata;
    backet->key = key;
    backet->next = hash->index[index];
    hash->index[index] = backet;
    hash->count++;
  
    return backet->data;
}

/* XXX:chenshaohong@ruijie.com.cn release the data from hash and add it again */
void *lib_hash_move(struct hash *hash, void *data, unsigned int newkey)
{
    unsigned int key;
    unsigned int index;
    struct hash_backet *backet;
    struct hash_backet *pp;
  
    key = (*hash->hash_key)(data);
    index = key % hash->size;

    for (backet = pp = hash->index[index]; backet; backet = backet->next) {
        if (backet->key == key && (*hash->hash_cmp)(backet->data, data)) {
            if (backet == pp) {
                hash->index[index] = backet->next;
            } else {
                pp->next = backet->next;
            }
            hash->count--;
            break;
         }
         pp = backet;
    }
   
    if (backet == NULL) {
        backet = malloc(sizeof (struct hash_backet));
        if (backet == NULL) {
            return NULL;
        }
    } else {
        pp->next = backet->next;
    }
    
    index = newkey % hash->size;
    backet->key = newkey;
    backet->next = hash->index[index];
    hash->index[index] = backet;
    hash->count++;

    return backet->data;
}

/* Hash lookup.  */
void *lib_hash_lookup(struct hash *hash, void *data)
{
    return lib_hash_get(hash, data, NULL);
}

/* This function release registered value from specified hash.  When
   release is successfully finished, return the data pointer in the
   hash backet.  */
void *lib_hash_release(struct hash *hash, void *data)
{
    void *ret;
    unsigned int key;
    unsigned int index;
    struct hash_backet *backet;
    struct hash_backet *pp;

    key = (*hash->hash_key)(data);
    index = key % hash->size;

    for (backet = pp = hash->index[index]; backet; backet = backet->next) {
        if (backet->key == key && (*hash->hash_cmp)(backet->data, data)) {
            if (backet == pp) {
                hash->index[index] = backet->next;
            } else {
                pp->next = backet->next;
            }

            ret = backet->data;
            free(backet);
            hash->count--;
            return ret;
        }
        pp = backet;
    }
    return NULL;
}

/* Iterator function for hash.  */
void lib_hash_iterate(struct hash *hash, void (*func)(struct hash_backet *, void *), void *arg)
{
    struct hash_backet *hb;
    int i;

    for (i = 0; i < hash->size; i++) {
        for (hb = hash->index[i]; hb; hb = hb->next) {
            (*func)(hb, arg);
        }
    }
}

/* Iterator function for hash with 2 args  */
void lib_hash_iterate2(struct hash *hash, void (*func)(struct hash_backet *, void *, void *),
                   void *arg1, void *arg2)
{
    struct hash_backet *hb;
    int i;

    for (i = 0; i < hash->size; i++) {
        for (hb = hash->index[i]; hb; hb = hb->next) {
            (*func)(hb, arg1, arg2);
        }
    }
}

/* Iterator function for hash with 3 args  */
void lib_hash_iterate3(struct hash *hash, void (*func)(struct hash_backet *, void *, void *, void *),
                   void *arg1, void *arg2, void *arg3)
{
    struct hash_backet *hb;
    int i;

    for (i = 0; i < hash->size; i++) {
        for (hb = hash->index[i]; hb; hb = hb->next) {
            (*func)(hb, arg1, arg2, arg3);
        }
    }
}

/* Clean up hash.  */
void lib_hash_clean(struct hash *hash, void (*free_func)(void *))
{
    int i;
    struct hash_backet *hb;
    struct hash_backet *next;

    for (i = 0; i < hash->size; i++) {
        for (hb = hash->index[i]; hb; hb = next) {
            next = hb->next;

            if (free_func) {
                (*free_func)(hb->data);
            }

            free (hb);
            hash->count--;
        }
        hash->index[i] = NULL;
    }
}

/* Free hash memory.  You may call hash_clean before call this function.  */
void lib_hash_free(struct hash *hash)
{
    free(hash->index);
    free(hash);
}

/* lindn - Delete partial data */
void lib_hash_clean_cmp(struct hash *hash, void (*free_func)(void *), 
                        int (*hash_cmp)(void *, void *), void *data)
{
    int i;
    struct hash_backet *hb;
    struct hash_backet *next;
    struct hash_backet *pp;

    for (i = 0; i < hash->size; i++) {
        for (hb = pp = hash->index[i]; hb; hb = next) {
            next = hb->next;

            if ((*hash_cmp)(hb->data, data)) {
                if (hb == pp) {
                    hash->index[i] = hb->next;
                    pp = hb->next;
                } else {
                    pp->next = hb->next;
                }

                if (free_func) {
                    (*free_func)(hb->data);
                }

                free(hb);
                hash->count--;
            } else {
                pp = hb;
            }
        }
    }
    return;
}

/* times 33 ¹þÏ£Ëã·¨ */
unsigned int hash_key_fun(char *hash_key)
{
    unsigned int hash = 0;
    const unsigned char *key = (const unsigned char *)hash_key;
    const unsigned char *p;
    int i;
    int klen = strlen((const char *)key);

    for (p = key, i = klen; i; i--, p++) {
        hash = hash * 33 + *p;
    }

    return hash;
}


/* zhangwangpeng@ruijie.com.cn */
struct hash *hash_create(unsigned int (*hash_key)(char *), int (*hash_cmp)(void *, void *))
{
    return lib_hash_create_size(HASHTABSIZE, hash_key, hash_cmp);
}

/* zhangwangpeng@ruijie.com.cn */
void *hash_set(struct hash *hash, char *hash_key, void *hash_value)
{
    unsigned int key;
    unsigned int index;
    void *newdata;
    struct hash_backet *backet;
    void *pfind;


    key = (*hash->hash_key)(hash_key);
    index = key % hash->size;

    pfind = NULL;
    for (backet = hash->index[index]; backet != NULL; backet = backet->next) {
        if (backet->key == key && (*hash->hash_cmp)(backet->data, hash_key)) {
            pfind =  backet->data;
        }
    }

    if (!pfind) {
        newdata = hash_value;
        if (newdata == NULL) {
            return NULL;
        }

        backet = malloc(sizeof(struct hash_backet));
        if (backet == NULL) {
            return NULL;
        }
        backet->data = newdata;
        backet->key = key;
        backet->next = hash->index[index];
        hash->index[index] = backet;
        hash->count++;
        return backet->data;
    }

    return NULL;
}

/* zhangwangpeng@ruijie.com.cn */
void *hash_get(struct hash *hash, char *hash_key)
{
    unsigned int key;
    unsigned int index;
    struct hash_backet *backet;

    key = (*hash->hash_key)(hash_key);
    index = key % hash->size;

    for (backet = hash->index[index]; backet != NULL; backet = backet->next) {
        if (backet->key == key && (*hash->hash_cmp)(backet->data, hash_key)) {
            return backet->data;
        }
    }

    return NULL;
}

/* zhangwangpeng@ruijie.com.cn */
void hash_clean(struct hash *hash, void (*free_func)(void *))
{
    int i;
    struct hash_backet *hb;
    struct hash_backet *next;

    for (i = 0; i < hash->size; i++) {
        for (hb = hash->index[i]; hb; hb = next) {
            next = hb->next;

            if (free_func) {
                (*free_func)(hb->data);
            }

            free (hb);
            hash->count--;
        }
        hash->index[i] = NULL;
    }
}

/* zhangwangpeng@ruijie.com.cn */
void hash_destroy(struct hash *hash, void (*free_func)(void *))
{
    int i;
    struct hash_backet *hb;
    struct hash_backet *next;

    for (i = 0; i < hash->size; i++) {
        for (hb = hash->index[i]; hb; hb = next) {
            next = hb->next;

            if (free_func) {
                (*free_func)(hb->data);
            }

            free (hb);
            hash->count--;
        }
        hash->index[i] = NULL;
    }

    free(hash);
}

/* zhangwangpeng@ruijie.com.cn */
void hash_delete_node(struct hash *hash, void (*free_func)(void *), int (*hash_cmp)(void *, void *), 
        void *data)
{
    int i;
    struct hash_backet *hb;
    struct hash_backet *next;
    struct hash_backet *pp;

    for (i = 0; i < hash->size; i++) {
        for (hb = pp = hash->index[i]; hb; hb = next) {
            next = hb->next;
            if ((*hash_cmp)(hb->data, data)) {
                if (hb == pp) {
                    hash->index[i] = hb->next;
                    pp = hb->next;
                } else {
                    pp->next = hb->next;
                }
                if (free_func) {
                    (*free_func)(hb->data);
                }
                free(hb);
                hash->count--;
            } else {
                pp = hb;
            }
        }
    }
    
    return;
}

