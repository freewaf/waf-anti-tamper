/*
 * $Id: svn.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#ifndef _SVN_H_
#define _SVN_H_

#include <string.h>
#include <stdlib.h>
#include "list.h"
#include "hash.h"

#define ACTION_UPDATE 0
#define ACTION_DELETE 1
#define ACTION_ADD    2
#define TYPE_FILE     1
#define TYPE_DIR      2

typedef struct svn_node_s {
    struct list_head brother;
    int version;
    int action;
    int file_type;
    int isstored;
    unsigned long tampertime;
    unsigned long detecttime;
    unsigned long restoretime;
    char *filename;
} svn_node_t;

typedef struct svn_s {
    int last_version;
    int changed;
    struct hash *svnhash;
    svn_node_t update_files;
    svn_node_t add_files;
    svn_node_t delete_files;
} svn_t;

extern svn_t *svn_init();
extern int svn_add_record(svn_t *svn, svn_t *mansvn, svn_t *reversesvn, char *filename, 
            int action_type, int file_type, unsigned long tampertime, unsigned long detecttime, 
            unsigned long restoretime);
extern void svn_commit(svn_t *svn);
extern int svn_get_lastversion(svn_t *svn);
extern svn_node_t *svn_get_node(svn_t *svn, char *filename);
extern void svn_del_node(svn_t *svn, svn_node_t *node);
extern void svn_add_node(svn_t *svn, svn_node_t *node);
extern void svn_del_all_record(svn_t *svn);
extern void svn_uninit(svn_t *svn);
extern void svn_copy_record(svn_t *svn_from, svn_t *svn_to);

#endif

