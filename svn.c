/*
 * $Id: svn.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
 *
 * (C) 2013-2014 see FreeWAF Development Team
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file LICENSE.GPLv2.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *  http://www.gnu.org/licenses/gpl-2.0.html
 *
 */
#include "svn.h"

static int svn_cmp_fun(void *param1, void *param2)
{
    svn_node_t *node;
    char *filename; 

    node = (svn_node_t *)param1;
    filename = (char *)param2;

    if (node == NULL || filename == NULL || node->filename == NULL) {
        return 0;
    }
    
    return !strcmp(node->filename, filename);
}

svn_t *svn_init()
{
    svn_t *svn = (svn_t *)malloc(sizeof(svn_t));
    if (svn == NULL) {
        return NULL;
    }

    svn->last_version = 1;
    svn->changed = 0;
    INIT_LIST_HEAD(&svn->delete_files.brother);
    INIT_LIST_HEAD(&svn->add_files.brother);
    INIT_LIST_HEAD(&svn->update_files.brother);
    svn->svnhash = hash_create(hash_key_fun, svn_cmp_fun);
    if (svn->svnhash == NULL) {
        free(svn);
        return NULL;
    }

    return svn;
}

static int list_add_record(struct hash *svnhash, struct hash *man_restorehash, 
            struct hash *man_reservehash, svn_node_t *head, char *filename, int type, int file_type, 
            int last_version, unsigned long tampertime, unsigned long detecttime, 
            unsigned long restoretime)
{
    if (!hash_get(svnhash, filename) 
            && !hash_get(man_restorehash, filename)
            && !hash_get(man_reservehash, filename)) {
        svn_node_t *node = (svn_node_t *)malloc(sizeof(svn_node_t));
        if (node == NULL) {
            return 1;
        }
        
        node->filename = (char *)malloc(strlen(filename) + 1);
        if (node->filename == NULL) {
            free(node);
            return 1;
        }
        strcpy(node->filename, filename);
        node->action = type;
        node->file_type = file_type;
        node->version = last_version;
        node->isstored = 0;
        node->tampertime = tampertime;
        node->detecttime = detecttime;
        node->restoretime = restoretime;
        list_add_tail(&node->brother, &head->brother);
        hash_set(svnhash, node->filename, node);
        
        return 1;
    }

    return 0;
}

int svn_add_record(svn_t *svn, svn_t *mansvn, svn_t *reservesvn, char *filename, int action_type, 
        int file_type, unsigned long tampertime, unsigned long detecttime, unsigned long restoretime)
{
    int rv = 0;
    
    if (svn == NULL || mansvn == NULL || reservesvn == NULL || filename == NULL) {
        return -1;
    }
    
    switch (action_type) {
    case ACTION_UPDATE:
        rv = list_add_record(svn->svnhash, mansvn->svnhash, reservesvn->svnhash, &svn->update_files, 
                filename, ACTION_UPDATE, file_type, svn->last_version, tampertime, detecttime, 
                restoretime);
        break;
    case ACTION_ADD:
        rv = list_add_record(svn->svnhash, mansvn->svnhash, reservesvn->svnhash, &svn->add_files, 
                filename, ACTION_ADD, file_type, svn->last_version, tampertime, detecttime, 
                restoretime);
        break;
    case ACTION_DELETE:
        rv = list_add_record(svn->svnhash, mansvn->svnhash, reservesvn->svnhash, &svn->delete_files, 
                filename, ACTION_DELETE, file_type, svn->last_version, tampertime, detecttime, 
                restoretime);
        break;
    }
    
    svn->changed = 1;
    
    return rv;
}

void svn_copy_record(svn_t *svn_from, svn_t *svn_to)
{
    svn_node_t *tmp;
    struct list_head *pos;
    struct list_head *postmp;
    
    if (svn_from == NULL || svn_to == NULL) {
        return;
    }
    
    list_for_each_safe(pos, postmp, &svn_from->add_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp) {
            svn_del_node(svn_from, tmp);
            svn_add_node(svn_to, tmp);
        }
    }

    list_for_each_safe(pos, postmp, &svn_from->update_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp) {
            svn_del_node(svn_from, tmp);
            svn_add_node(svn_to, tmp);
        }
    }

    list_for_each_safe(pos, postmp, &svn_from->delete_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp) {
            svn_del_node(svn_from, tmp);
            svn_add_node(svn_to, tmp);
        }
    }
}

svn_node_t *svn_get_node(svn_t *svn, char *filename)
{
    if (svn == NULL || filename == NULL) {
        return NULL;
    }
    
    return hash_get(svn->svnhash, filename);
}

void svn_del_node(svn_t *svn, svn_node_t *node)
{
    if (svn == NULL || node == NULL) {
        return;
    }
    
    list_del_init(&node->brother);
    hash_delete_node(svn->svnhash, NULL, svn_cmp_fun, node->filename);
}

void svn_add_node(svn_t *svn, svn_node_t *node)
{
    if (svn == NULL || node == NULL) {
        return;
    }

    switch(node->action) {
    case ACTION_UPDATE:
        if (!hash_get(svn->svnhash, node->filename)) {
            list_add_tail(&node->brother, &svn->update_files.brother);
            hash_set(svn->svnhash,node->filename, node);
        }
        break;
    case ACTION_DELETE:
        if (!hash_get(svn->svnhash, node->filename)) {
            list_add_tail(&node->brother, &svn->delete_files.brother);
            hash_set(svn->svnhash, node->filename, node);
        }
        break;
    case ACTION_ADD:
        if (!hash_get(svn->svnhash, node->filename)) {
            list_add_tail(&node->brother, &svn->add_files.brother);
            hash_set(svn->svnhash, node->filename, node);
        }
        break;
    }
}

void svn_del_all_record(svn_t *svn)
{
    svn_node_t *tmp;
    struct list_head *pos;
    struct list_head *postmp;

    if(svn == NULL) {
        return;
    }

    list_for_each_safe(pos, postmp, &svn->add_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp) {
            free(tmp->filename);
            tmp->filename = NULL;
            list_del_init(&tmp->brother);
            free(tmp);
            tmp = NULL;
        }
    }

    list_for_each_safe(pos, postmp, &svn->update_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp) {
            free(tmp->filename);
            tmp->filename = NULL;
            list_del_init(&tmp->brother);
            free(tmp);
            tmp = NULL;
        }
    }

    list_for_each_safe(pos, postmp, &svn->delete_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp) {
            free(tmp->filename);
            tmp->filename = NULL;
            list_del_init(&tmp->brother);
            free(tmp);
            tmp = NULL;
        }
    }
    
    hash_clean(svn->svnhash, NULL);
}

void svn_commit(svn_t *svn)
{
    if (svn == NULL) {
        return;
    }
    
    if (svn->changed) {
        svn->last_version++;
        svn->changed = 0;
    }
}

int svn_get_lastversion(svn_t *svn)
{
    if (svn == NULL) {
        return 0;
    }
    
    return svn->last_version;
}

void svn_uninit(svn_t *svn)
{
    if (svn == NULL) {
        return;
    }

    hash_destroy(svn->svnhash, NULL);
}

