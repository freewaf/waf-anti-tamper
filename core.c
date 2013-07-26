/*
 * $Id: core.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "core.h"
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <utime.h>
#include <apr_time.h>
#include "print.h"
#include "list.h"
#include "protocol_sftp.h"
#include "util.h"
#include "tree.h"
#include "svn.h"
#include "hash.h"
#include "stack.h"
#include "log.h"
#include "cli_unix.h"

#define FILE_DOWNLOAD                1
#define FILE_COMPARE                 2
#define FILE_COUNT                   3

#define MAN_RESTORE                  1
#define AUTO_RESTORE                 2

#define CFG_STATUS_UNCHANGED         0
#define CFG_STATUS_REBACKUP          1
#define CFG_STATUS_PROTOCHG          (1 << 1)
#define CFG_STATUS_DESTROYWB         (1 << 2)

#define SUCCESS                      0
#define ERROR_EXCEED_TOTALDISKSIZE   1

/* 设置本地文件属性 */
static void set_fileinfo_local(char *filename, file_t *attrs)
{
    struct utimbuf amtime;
    int ret;

    amtime.actime = attrs->atime;
    amtime.modtime = attrs->mtime;

    /* 设置atime和mtine */
    ret = utime(filename, &amtime);
    if (ret < 0) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "set file %s time failed.", filename);
    }

    /* 设置权限 */
    ret = chmod(filename, attrs->permissions);
    if (ret < 0) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "set file %s mode failed.", filename);
    }
}

/* 本地写文件 */
static void write_file_to_local(protocol_data_t *protocol, char *filesp, char *filedp, 
                file_t *attrs)
{
    int fp;
    int rc;
    int ret;

    ret = protocol_open_file_for_read(protocol, filesp);
    if (ret != 0 ) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "unable to open file with SFTP.");
        return;
    }

    /* 创建文件，清除内容 */
    fp = open(filedp, O_WRONLY | O_CREAT | O_TRUNC, attrs->permissions);
    if (fp == 0) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "unable to open file %s.", filedp);
        return;
    }

    do {
        char buffer[1024] = {0};
        rc = protocol_read_file(protocol, buffer, sizeof(buffer));
        if (rc > 0) {
            lseek(fp, 0, SEEK_END);
            write(fp, buffer, rc);
        } else {
            break;
        }
    } while (1);

    close(fp);
    protocol_close_file(protocol);
}

/* 设置远程文件属性 */
static int set_fileinfo_server(protocol_data_t *protocol, char *filesp, char *filedp)
{
    struct stat fs;
    file_t fileinfo;
    int ret;

    ret = lstat(filesp, &fs);
    if (ret != 0) {
        return -1;
    }

    fileinfo.filesize = fs.st_size;
    fileinfo.uid = fs.st_uid;
    fileinfo.gid = fs.st_gid;
    fileinfo.permissions = fs.st_mode;
    fileinfo.atime = fs.st_atime;
    fileinfo.mtime = fs.st_mtime;

    return protocol_set_stat(protocol, filedp, &fileinfo);
}

/* 写远程文件 */
static void write_file_to_server(protocol_data_t *protocol, char *filesp, char *filedp)
{
    int fp;
    int rc;
    int ret;
    char *ptr;
    char buffer[1024];
    int nread;

    /* 前导路径 */
    ret = protocol_open_file_for_write(protocol, filedp);
    if (ret != 0 ) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "unable to open file %s with SFTP\n", filedp);
        return;
    }

    /* 创建文件，清除内容 */
    fp = open(filesp, O_RDONLY);
    if (fp == 0) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "unable to open file %s\n", filesp);
        protocol_close_file(protocol);
        return;
    }

    do {
        nread = read(fp, buffer, sizeof(buffer));
        if (nread <= 0) {
            break;
        }
        ptr = buffer;

        do {
            rc = protocol_write_file(protocol, ptr, nread);
            if(rc <= 0) {
                break;
            }
            ptr += rc;
            nread -= rc;
        } while (nread);
    } while (rc > 0);

    close(fp);
    protocol_close_file(protocol);
}

/* 本地创建文件夹 */
static void mkdir_local(char *dirname, long permissions)
{
    mkdir(dirname, permissions);
}

/* 远程创建文件夹 */
static int mkdir_server(protocol_data_t *protocol, char *filesp, char *filedp)
{
    int ret;
    struct stat fs;

    ret = lstat(filesp, &fs);
    if (ret != 0) {
        return -1;
    }

    return protocol_write_dir(protocol, filedp, fs.st_mode);
}

/* 节点填充 */
static int fill_node(char *fullfilename, directory_t *node, file_t *fileinfo, int type)
{
    node->name = (char *)malloc(strlen(fileinfo->filename) + 2);
    if (node->name == NULL) {
        return -1;
    }

    strcpy(node->name, fileinfo->filename);
    if (type == NODE_DIR && !strchr(fileinfo->filename, '/')) {
        strcat(node->name, "/");
    }

    node->md5_value = md5_value_align(node->md5_value_unaligned, MD5_ALIGN);
    md5_generate_value(fullfilename, node->md5_value);

    node->isfile = type;
    node->filesize = fileinfo->filesize;
    node->gid = fileinfo->gid;
    node->uid = fileinfo->uid;
    node->permissions = fileinfo->permissions;
    node->mtime = fileinfo->mtime;
    node->atime = fileinfo->atime;
    node->touched = TYPE_UNTOUCHED;

    return 0;
}

/* 目录树添加节点 */
static directory_t *add_dir_node(char *fullfilename, file_t *fileinfo, directory_t *parent,
                    int node_type)
{
    directory_t *node;
    int ret;

    if (parent == NULL) {
        return NULL;
    }

    /* 创建目录树节点 */
    node = (directory_t *)malloc(sizeof(directory_t));
    if (node == NULL) {
        return NULL;
    }

    memset(node, 0, sizeof(directory_t));

    /* 获取属性 */
    ret = fill_node(fullfilename, node, fileinfo, node_type);
    if (ret == -1) {
        return NULL;
    }

    /* 插入目录树  */
    ret = dir_add_node(parent, node);
    if (ret == -1) {
        free(node->name);
        free(node);
        return NULL;
    }

    return node;
}

/* 添加哈希节点 */
static int add_hash_node(char *fullfilename, directory_t *node, struct hash *hash)
{
    /* 插入哈希表 */
    hash_set(hash, fullfilename, node);

    return 0;
}

/* 轮询 */
static int compare(webserver_t *wb, directory_t *root, struct hash *hash, char *srcfilename,
            char *destfilename, file_t *filestat, svn_t *svn)
{
    directory_t *node;
    svn_node_t *svnnode;
    int backup;
    char chfilename[MAX_PATH_LEN] = {0};
    unsigned char md5_value_unaligned[MD5_BYTES + MD5_ALIGN];
    unsigned char *md5_value;
    int file_type;
    int rv;

    if (S_ISREG(filestat->permissions)) {
        file_type = TYPE_FILE;
    } else {
        file_type = TYPE_DIR;
    }

    backup = 0;
    svnnode = svn_get_node(svn, destfilename);
    if (!svnnode) { 
        backup = 1;
    }

    node = hash_get(hash, destfilename);
    if (node == NULL) {
#if 0        
        if (backup) {
            sprintf(chfilename, "%s%s", wb->change_root, srcfilename + strlen(wb->cfg.server_root));
            make_previous_dir(chfilename);
            write_file_to_local(wb->protocol, srcfilename, chfilename, filestat);
        }
#endif      

        rv =svn_add_record(svn, wb->man_restore, wb->man_reserve, destfilename, ACTION_ADD, file_type, filestat->atime,
                apr_time_sec(apr_time_now()), 0);
        if (rv) {
            wb->changednum++;
            send_detect_log(wb->cfg.host);
        }
        return -1;
    }   
    
    if (node->touched == TYPE_UNTOUCHED && S_ISREG(filestat->permissions)) {
        if (node->filesize != filestat->filesize) {
            if (backup) {
                sprintf(chfilename, "%s%s", wb->change_root, 
                    srcfilename + strlen(wb->cfg.server_root));
                make_previous_dir(chfilename);
                write_file_to_local(wb->protocol, srcfilename, chfilename, filestat);
            }
            
            rv = svn_add_record(svn, wb->man_restore, wb->man_reserve, destfilename, ACTION_UPDATE, file_type, filestat->mtime,
                    apr_time_sec(apr_time_now()), 0);
            if (rv) {
                wb->changednum++;      
                send_detect_log(wb->cfg.host);
            }
            node->touched = TYPE_TOUCHED;
            return -1;
        }

        if (difftime(node->mtime, filestat->mtime)) {
            if (backup) {
                sprintf(chfilename, "%s%s", wb->change_root, 
                    srcfilename + strlen(wb->cfg.server_root));
                make_previous_dir(chfilename);
                write_file_to_local(wb->protocol, srcfilename, chfilename, filestat);
            }

            md5_value = md5_value_align(md5_value_unaligned, MD5_ALIGN);
            md5_generate_value(chfilename, md5_value);
            if (memcmp(node->md5_value, md5_value, MD5_BYTES)) {
                rv = svn_add_record(svn, wb->man_restore, wb->man_reserve, destfilename, ACTION_UPDATE, file_type, filestat->mtime,
                        apr_time_sec(apr_time_now()), 0);
                if (rv) {
                    wb->changednum++;
                    send_detect_log(wb->cfg.host);
                }
                node->touched = TYPE_TOUCHED;
                return -1;
            }
        }
    }
    
    node->touched = TYPE_TOUCHED;
    
    return 0;
}

/* 遍历目录树 */
static void walk_dirtree(webserver_t *wb, directory_t *dir, svn_t *svn, svn_t *man_restore, svn_t *man_reserve, int depth)
{
    directory_t *head;
    directory_t *tmp;
    struct list_head *pos;
    char destfilename[MAX_PATH_LEN] = {0};
    int rv;

    if(dir == NULL || dir->firstchild == NULL) {
        return;
    }

    if (depth <= 0) {
        return;
    }

    head = dir->firstchild;
    list_for_each(pos, &head->brother) {
        tmp = list_entry(pos, directory_t, brother);
        if (tmp->isfile) {
            if (tmp->touched == TYPE_TOUCHED) {
                tmp->touched = TYPE_UNTOUCHED;
            } else {
                dir_get_local_path(tmp, destfilename, MAX_PATH_LEN);
                /* 被删除的文件或者文件夹，被篡改的时间就是轮询的时间 */
                rv = svn_add_record(svn, man_restore, man_reserve, destfilename, ACTION_DELETE, TYPE_FILE, apr_time_sec(apr_time_now()),
                        apr_time_sec(apr_time_now()), 0);
                if (rv) {
                    wb->changednum++; 
                    send_detect_log(wb->cfg.host);
                }
                destfilename[0] = 0;
            }
        } else {
            if (tmp->touched == TYPE_TOUCHED) {
                tmp->touched = TYPE_UNTOUCHED;
            } else {
                dir_get_local_path(tmp, destfilename, MAX_PATH_LEN);
                rv = svn_add_record(svn, man_restore, man_reserve, destfilename, ACTION_DELETE, TYPE_DIR, apr_time_sec(apr_time_now()),
                        apr_time_sec(apr_time_now()), 0);
                if (rv) {
                    send_detect_log(wb->cfg.host);
                }
                destfilename[0] = 0;
            }
            walk_dirtree(wb, tmp, svn, man_restore, man_reserve, depth - 1);
        }
    }

    return;
}

/* 获取文件/文件夹深度 */
static int get_level(char *path, char *root)
{
    char *p;
    int level;

    p = strstr(path, root);
    if (p == NULL) {
        return 0;
    }

    p = p + strlen(root);
    level = 1;
    while((p = strchr(p, '/')) != NULL) {
        level++;
        p = p + 1;
    }

    return level;
}

static void push_to_stack(struct stack_s *stack, char *srcpath, char *dstpath, void *node)
{
    char *pair_src;
    char *pair_des;
    addrpair_t pair;

    pair_src = (char *)malloc(strlen(srcpath) + 1);
    if (pair_src == NULL) {
        return;
    }

    pair_des = (char *)malloc(strlen(dstpath) + 1);
    if (pair_des == NULL) {
        free(pair_src);
        return;
    }   
   
    strcpy(pair_src, srcpath);
    strcpy(pair_des, dstpath);

    pair.parent = node;
    pair.source = pair_src;
    pair.dest = pair_des;

    stack_push(stack, pair);
}

static int list_files(protocol_data_t *protocol, webserver_t *wb, webserver_cfg_t *wscfg,
            directory_t *dir, char *srcpath, char *dstpath, int depth, int type)
{
    int ret;
    char *filelist;
    int filecount;
    int i;
    unsigned long permissions;
    unsigned long long filesize;
    file_t *fileinfo;
    char *filename;
    char *p;
    int level;
    directory_t *node;
    directory_t *parent;
    struct hash *hash = wb->dirhash;
    int maxfilesize = wscfg->maxfilesize;
    char source[MAX_PATH_LEN];
    char dest[MAX_PATH_LEN];
    addrpair_t pair;
    struct stack_s *stack;
    char *osrcpath;
    char *odstpath;

    osrcpath = (char *)malloc(strlen(srcpath) + 1);
    if (osrcpath == NULL) {
        return ERROR_MALLOC_FAILED;
    }
    strcpy(osrcpath, srcpath);

    odstpath = (char *)malloc(strlen(dstpath) + 1);
    if (odstpath == NULL) {
        free(osrcpath);
        return ERROR_MALLOC_FAILED;
    }
    strcpy(odstpath, dstpath);

    stack = stack_create();
    if (stack == NULL) {
        free(osrcpath);
        free(odstpath);
        return ERROR_MALLOC_FAILED;  
    }
    
    push_to_stack(stack, osrcpath, odstpath, dir);
         
    while (!stack_isempty(stack)) {
        pair = stack_top(stack);
        strcpy(source, pair.source);
        strcpy(dest, pair.dest);
        parent = (directory_t *)pair.parent;
        free(pair.source);
        free(pair.dest);
        stack_pop(stack);
      
        ret = protocol_open_dir(protocol, source);
        if (ret != 0) {
            TAMPER_LOG_WRITE(PE_LOG_INFO, "open dir %s failed.", source);
            return -1;
        }

        /* filelist动态申请的内存 */
        ret = protocol_get_list(protocol, &filelist, &filecount);
        if (ret != 0) {
            TAMPER_LOG_WRITE(PE_LOG_INFO, "get file list failed.");
            protocol_close_dir(protocol);
            return -1;
        }

        protocol_close_dir(protocol);

        fileinfo = (file_t *)filelist;
        for (i = 0; i < filecount; i++) {
            filename = (fileinfo + i)->filename;
            filesize = (fileinfo + i)->filesize;
            permissions = (fileinfo + i)->permissions;           

            /* 文件 */
            if (S_ISREG(permissions)) {
                add_lastfilename(source, filename);
                add_lastfilename(dest, filename);

                if (type != FILE_COUNT) {
                    /* 超过一定大小的不进行保护 */
                    if (filesize >= maxfilesize) {
                        del_lastfilename(source);
                        del_lastfilename(dest);
                        continue;
                    }

                    /* 某些后缀的文件不进行包含 */
                    suffix_t *old_suffix;
                    int found;

                    found = 0;
                    p = strrchr(source, '.');
                    if (p) {
                        list_for_each_entry(old_suffix, &(wscfg->suffix_head), list, suffix_t) {
                            if (!strcmp(old_suffix->suffix, p + 1)) {
                                del_lastfilename(source);
                                del_lastfilename(dest);
                                found++;
                                break;
                            }
                        }
                    }

                    if (found) {
                        continue;
                    }
                }

                if (type == FILE_DOWNLOAD) {
                    wb->backupsize += filesize;
                    wb->backupnum++;
                    if (wb->backupsize >= wb->cfg.disksize) {
                        free(filelist);
                        stack_destroy(stack);
                        return ERROR_EXCEED_TOTALDISKSIZE;
                    }

                    write_file_to_local(protocol, source, dest, (fileinfo + i));
                    set_fileinfo_local(dest, fileinfo + i);/* 修改文件属性和时间 */
                    node = add_dir_node(dest, fileinfo + i, parent, NODE_FILE);
                    add_hash_node(dest, node, hash);
                } else if (type == FILE_COMPARE) {
                    compare(wb, wb->dirtree, wb->dirhash, source, dest, fileinfo + i, wb->svn);
                } else if (type == FILE_COUNT) {
                    wb->totalnum++;
                }

                del_lastfilename(source);
                del_lastfilename(dest);
            }

            /* 文件夹 */
            if (S_ISDIR(permissions)) {
                add_lastdirname(source, filename);
                add_lastdirname(dest, filename);

                if (type == FILE_DOWNLOAD) {
                    mkdir_local(dest, permissions);
                    set_fileinfo_local(dest, fileinfo + i);/* 修改文件属性和时间 */
                    node = add_dir_node(dest, fileinfo + i, parent, NODE_DIR);
                    add_hash_node(dest, node, hash);
                } else if (type == FILE_COMPARE) {
                    compare(wb, wb->dirtree, wb->dirhash, source, dest, fileinfo + i, wb->svn);
                }

                /* 获取级别 */
                level = get_level(source, srcpath);
                if (level <= depth) {
                    push_to_stack(stack, source, dest, node);
                }

                del_lastdirname(source);
                del_lastdirname(dest);
            }
        }
        free(filelist);
    }

    stack_destroy(stack);
   
    return 0;
}

/* 获取服务器总文件数 */
static int count_file_total_num(protocol_data_t *protocol, webserver_t *wb, webserver_cfg_t *wscfg,
            directory_t *dir, char *srcpath, char *dstpath, int depth)
{
    return list_files(wb->protocol, wb, wscfg, wb->dirtree, wb->cfg.server_root, wb->local_root,
            depth, FILE_COUNT);
}

/* 全额下载文件 */
static int ful_download_file(protocol_data_t *protocol, webserver_t *wb, webserver_cfg_t *wscfg,
            directory_t *dir, char *srcpath, char *dstpath, int depth)
{
    return list_files(wb->protocol, wb, wscfg, wb->dirtree, wb->cfg.server_root, wb->local_root,
            depth, FILE_DOWNLOAD);
}

/* 文件比较 */
static int compare_file(protocol_data_t *protocol, webserver_t *wb, webserver_cfg_t *wscfg,
            directory_t *dir, char *srcpath, char *dstpath, int depth)
{
    int ret;

    ret = list_files(wb->protocol, wb, wscfg, wb->dirtree, wb->cfg.server_root, wb->local_root,
            depth, FILE_COMPARE);
    if (ret != 0) {
        goto __exit;
    }

    walk_dirtree(wb, dir, wb->svn, wb->man_restore, wb->man_reserve, depth);

__exit:
    return ret;
}

/* 增量下载文件 */
static int inc_download_file(protocol_data_t *protocol, webserver_t *wb, svn_t *svn, char *local_root, 
            char *server_root)
{
    struct list_head *pos;
    struct list_head *tmppos;
    svn_node_t *tmp;
    directory_t *parent;
    directory_t *root = wb->dirtree;
    struct hash *hash = wb->dirhash;
    directory_t *node;
    file_t fileinfo;
    char svrfilename[MAX_PATH_LEN] = {0};
    char *p, *q;

    list_for_each_safe(pos, tmppos, &svn->add_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp == NULL) {
            continue;
        }
        tmp->restoretime = apr_time_sec(apr_time_now());
        sprintf(svrfilename, "%s%s", server_root, tmp->filename + strlen(local_root));
        if (tmp->file_type == TYPE_FILE) {
            protocol_get_stat(protocol, svrfilename, &fileinfo);
            
            wb->backupsize += fileinfo.filesize;
            if (wb->backupsize >= wb->cfg.disksize) {
                return ERROR_EXCEED_TOTALDISKSIZE;
            }
            wb->backupnum++;
            wb->totalnum++;
                    
            write_file_to_local(protocol, svrfilename, tmp->filename, &fileinfo);
            set_fileinfo_local(tmp->filename, &fileinfo);

            p = strrchr(tmp->filename, '/');
            if (p) {
                strcpy(fileinfo.filename , p + 1);
            }
                                
            parent = dir_get_parent_node(root, tmp->filename, NODE_FILE);
            node = add_dir_node(tmp->filename, &fileinfo, parent, NODE_FILE);
            add_hash_node(tmp->filename, node, hash);
        } else if (tmp->file_type == TYPE_DIR) {
            protocol_get_stat(protocol, svrfilename, &fileinfo);
            mkdir_local(tmp->filename, fileinfo.permissions);
            set_fileinfo_local(tmp->filename, &fileinfo);

            p = strrchr(tmp->filename, '/');
            q = p;
            *p = 0;
            p = strrchr(tmp->filename, '/');
            *q = '/';
            if (p) {
                strcpy(fileinfo.filename , p + 1);
            }
 
            parent = dir_get_parent_node(root, tmp->filename, NODE_DIR);
            node = add_dir_node(tmp->filename, &fileinfo, parent, NODE_DIR);
            add_hash_node(tmp->filename, node, hash);
        }
    }

    list_for_each_safe(pos, tmppos, &svn->update_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp == NULL) {
            continue;
        }
        tmp->restoretime = apr_time_sec(apr_time_now());
        sprintf(svrfilename, "%s%s", server_root, tmp->filename + strlen(local_root));
        if (tmp->file_type == TYPE_FILE) {   
            protocol_get_stat(protocol, svrfilename, &fileinfo);
            write_file_to_local(protocol, svrfilename, tmp->filename, &fileinfo);
            set_fileinfo_local(tmp->filename, &fileinfo);
            node = dir_get_self_node(wb->dirtree, tmp->filename, NODE_FILE);
            if (node) {
                dir_update_node(node, &fileinfo);
                wb->backupsize -= node->filesize;
                wb->backupsize += fileinfo.filesize;
                if (wb->backupsize >= wb->cfg.disksize) {
                    return 0;
                }
            }
        } 
    }

    /* 删除哈希表 */
    list_for_each_safe(pos, tmppos, &svn->delete_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp == NULL) {
            continue;
        }
        tmp->restoretime = apr_time_sec(apr_time_now());
        if (tmp->file_type == TYPE_FILE) {
            node = dir_get_self_node(wb->dirtree, tmp->filename, NODE_FILE);
            if (node) {
                wb->backupsize -= node->filesize;
                wb->backupnum--;
                wb->totalnum--;
                unlink(tmp->filename);
                hash_delete_node(wb->dirhash, NULL, dir_cmp_fun2, node);
            }
        } else if (tmp->file_type == TYPE_DIR) {
            node = dir_get_self_node(wb->dirtree, tmp->filename, NODE_DIR);
            if (node) {
                delete_diskdir(tmp->filename);
                hash_delete_node(wb->dirhash, NULL, dir_cmp_fun2, node);
            }
        }
    }
  
    /* 删除目录树 */
    list_for_each_safe(pos, tmppos, &svn->delete_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        if (tmp == NULL) {
            continue;
        }
        
        if (tmp->file_type == TYPE_FILE) {
            node = dir_get_self_node(wb->dirtree, tmp->filename, NODE_FILE);
        } else if (tmp->file_type == TYPE_DIR) {
            node = dir_get_self_node(wb->dirtree, tmp->filename, NODE_DIR);
        }

        if (node) {
            dir_del_node(node);
        }
    }

    return 0;
}

static void restore_file(webserver_t *wb, protocol_data_t *protocol, svn_t *svn, char *local_root, 
            char *server_root)
{
    struct list_head *pos;
    struct list_head *tmppos;
    svn_node_t *tmp;
    char filename[MAX_PATH_LEN] = {0};

    list_for_each_safe(pos, tmppos, &svn->add_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        tmp->restoretime = apr_time_sec(apr_time_now());
        sprintf(filename, "%s%s", server_root, tmp->filename + strlen(local_root));
        if (tmp->file_type == TYPE_FILE) {
            protocol_rm_file(protocol, filename);
            wb->changednum--;
        } else {
            protocol_rm_dir(protocol, filename);
        }
    }

    list_for_each_safe(pos, tmppos, &svn->update_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        tmp->restoretime = apr_time_sec(apr_time_now());
        sprintf(filename, "%s%s", server_root, tmp->filename + strlen(local_root));
        write_file_to_server(protocol, tmp->filename, filename);
        set_fileinfo_server(protocol, tmp->filename, filename);
        wb->changednum--;
    }

    list_for_each_safe(pos, tmppos, &svn->delete_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        tmp->restoretime = apr_time_sec(apr_time_now());
        sprintf(filename, "%s%s", server_root, tmp->filename + strlen(local_root));
        if (tmp->file_type == TYPE_FILE) {
            write_file_to_server(protocol, tmp->filename, filename);
            set_fileinfo_server(protocol, tmp->filename, filename);
            wb->changednum--;
        } else {
            mkdir_server(protocol, tmp->filename, filename);
        }
    }
}

/* 自动恢复 */
static void auto_restore_file(webserver_t *wb, webserver_cfg_t *wscfg)
{
    restore_file(wb, wb->protocol, wb->svn, wb->local_root, wscfg->server_root);
    webtamper_log(wscfg->wsname, wscfg->host, "arestore", wb->svn, wb->local_root, 
        wscfg->server_root);
    svn_del_all_record(wb->svn);
    svn_commit(wb->svn);
    delete_diskfiles(wb->change_root);
    wb->changednum = 0;
}

/* 手动恢复 */
static void man_restore_file(webserver_t *wb, webserver_cfg_t *wscfg)
{
    restore_file(wb, wb->protocol, wb->man_restore, wb->local_root, wscfg->server_root); 
    webtamper_log(wscfg->wsname, wscfg->host, "mrestore", wb->man_restore, wb->local_root, 
        wscfg->server_root);
    svn_del_all_record(wb->man_restore);

    if (wscfg->iscomit) {
        inc_download_file(wb->protocol, wb, wb->man_reserve, wb->local_root, wscfg->server_root);
        webtamper_log(wscfg->wsname, wscfg->host, "mrestore", wb->man_reserve, wb->local_root, 
            wscfg->server_root);
        svn_del_all_record(wb->man_reserve);
        svn_commit(wb->man_reserve);
        delete_diskfiles(wb->change_root);
        
        wb->cfg.iscomit = 0;
        wb->changednum = 0;
    }
}

/* 配置更新 */
static int update_cfg(webserver_cfg_t *oldcfg, webserver_t *wb)
{
    int ret;
    int cfg_ret;

    cfg_ret = CFG_STATUS_UNCHANGED;

    /* 销毁Web服务器 */
    if (wb->cfg.destroywb) {
        oldcfg->destroywb = wb->cfg.destroywb;
        cfg_ret |= CFG_STATUS_DESTROYWB;
        return cfg_ret;
    }

    /* 不需要重新备份的配置 */
    oldcfg->debug = wb->cfg.debug;
    oldcfg->disksize = wb->cfg.disksize;
    oldcfg->enable = wb->cfg.enable;
    oldcfg->isautorestore = wb->cfg.isautorestore;
    oldcfg->other_interval = wb->cfg.other_interval;
    oldcfg->prtcl_port = wb->cfg.prtcl_port;
    oldcfg->root_interval = wb->cfg.root_interval;
    oldcfg->sysloglevel = wb->cfg.sysloglevel;
    oldcfg->iscomit = wb->cfg.iscomit;
    if (oldcfg->wsname[0] == '\0') {
        strcpy(oldcfg->wsname, wb->cfg.wsname);
    }

    cfg_copy(oldcfg->description, wb->cfg.description);
    cfg_copy(oldcfg->email, wb->cfg.email);
    cfg_copy(oldcfg->username, wb->cfg.username);
    cfg_copy(oldcfg->password, wb->cfg.password);
    
    /* 需要重新备份的配置  */
    ret = cfg_copy(oldcfg->prtcl_name, wb->cfg.prtcl_name);
    if (ret == CHANGED) {
        cfg_ret |= CFG_STATUS_PROTOCHG;
    }

    ret = cfg_copy(oldcfg->host, wb->cfg.host);
    if (ret == CHANGED) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    if (wb->suffix_changed) {
        suffix_t *new_suffix;
        suffix_t *old_suffix;
        suffix_t *tmp_suffix;

        list_for_each_entry_safe(old_suffix, tmp_suffix, &(oldcfg->suffix_head), list, suffix_t) {
            list_del_init(&(old_suffix->list));
            free(old_suffix);
        }
        
        list_for_each_entry(new_suffix, &(wb->cfg.suffix_head), list, suffix_t) {
            tmp_suffix = (suffix_t *)malloc(sizeof(suffix_t));
            if (tmp_suffix) {
                strncpy(tmp_suffix->suffix, new_suffix->suffix, MAX_SUFFIX_LEN);
                list_add_tail(&(tmp_suffix->list), &(oldcfg->suffix_head));
            }
        }

        wb->suffix_changed = 0;
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    ret = cfg_copy(oldcfg->server_root, wb->cfg.server_root);
    if (ret == CHANGED) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    if (oldcfg->depth != wb->cfg.depth) {
        oldcfg->depth = wb->cfg.depth;
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    if (oldcfg->maxfilesize != wb->cfg.maxfilesize) {
        oldcfg->maxfilesize = wb->cfg.maxfilesize;
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    return cfg_ret;
}

/* 配置检查 */
static int cheak_cfg(webserver_cfg_t *oldcfg, webserver_t *wb)
{
    int ret;
    int cfg_ret;

    cfg_ret = CFG_STATUS_UNCHANGED;

    /* 销毁Web服务器 */
    if (wb->cfg.destroywb) {
        cfg_ret |= CFG_STATUS_DESTROYWB;
        return cfg_ret;
    }
   
    /* 需要重新备份的配置  */
    ret = cfg_check(oldcfg->prtcl_name, wb->cfg.prtcl_name);
    if (ret == CHANGED) {
        cfg_ret |= CFG_STATUS_PROTOCHG;
    }

    ret = cfg_check(oldcfg->host, wb->cfg.host);
    if (ret == CHANGED) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    if (wb->suffix_changed) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    ret = cfg_check(oldcfg->server_root, wb->cfg.server_root);
    if (ret == CHANGED) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    if (oldcfg->depth != wb->cfg.depth) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    if (oldcfg->maxfilesize != wb->cfg.maxfilesize) {
        cfg_ret |= CFG_STATUS_REBACKUP;
    }

    return cfg_ret;
}

/**
 * worker_thread -  网页防篡改业务线程
 * @param arg: 相应的防篡改服务器结构
 *
 * 网页防篡改业务线程
 *
 * @returns
 *     失败: NULL
 */
void *worker_thread(void *arg)
{
    int ret;
    int cfg_ret;
    webserver_cfg_t wscfg;
    int incbak;
    int fulbak;
    int root_count;
    int other_count;
    apr_time_t start_time, end_time, delta_time;
    
    webserver_t *wb = (webserver_t *)arg;
    if (wb == NULL) {
        return NULL;
    }   

    cfg_ret = 0;
    incbak = 0;
    fulbak = 1;

    memset(&wscfg, 0, sizeof(webserver_cfg_t));
    INIT_LIST_HEAD(&(wscfg.suffix_head));   

    /* 初次提取配置并对具体的防篡改服务器做初始化 */
    pthread_mutex_lock(&list_mutex);
    ret = prepare_webserver(wb);
    if (ret == -1) {
        pthread_mutex_unlock(&list_mutex);
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "web server prepare failed.");
        return NULL;
    }
    update_cfg(&wscfg, wb);
    pthread_mutex_unlock(&list_mutex);

    TAMPER_LOG_WRITE(PE_LOG_FATAL, "web server [%s] start.", wb->cfg.wsname);

#if 0
    if (is_download_success(wb->markfile)) {
        TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] already downloaded fully.", wscfg.wsname);
        TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] build hash tree start.", wscfg.wsname);
        build_hashtree(wb->local_root, wb->dirtree, wb->dirhash);
        TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] build hash tree end.", wscfg.wsname);
        wb->isbackuped = 1;
    }
#endif

    /* 协议初始化 */
    //protocol_init(wb->protocol);
    while (1) {
        /* 检测配置是否更新  */
        pthread_mutex_lock(&list_mutex);
        cfg_ret = update_cfg(&wscfg, wb);
        pthread_mutex_unlock(&list_mutex);

        //fulbak = 0;

        /* 防篡改被删除 */
        if (cfg_ret & CFG_STATUS_DESTROYWB) {
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] is destroyed and exit.", wscfg.wsname);
            //protocol_uninit(wb->protocol);
            destroy_webserver(wb);
            /* 发送信号量 */
            sem_post(&wb->destroy_wait);
            return NULL;
        }
   
        /* 协议更换 */
        if (cfg_ret & CFG_STATUS_PROTOCHG) {
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] protocol changed.", wscfg.wsname);
            //protocol_uninit(wb->protocol);  /* 卸载原协议 */
            if (!strcmp(wb->protocol->protocol_name, "sftp")) {
                protocol_sftp_destroy(wb->protocol);
            }
            
            if (!strcmp(wscfg.prtcl_name, "sftp")) {
                wb->protocol = protocol_sftp_create();
                if (wb->protocol == NULL) {
                    continue;
                }
            }
            //protocol_init(wb->protocol);   /* 加载新协议 */
        }

        /* 关键配置更换需重新备份 */
        if ((cfg_ret & CFG_STATUS_REBACKUP) || (cfg_ret & CFG_STATUS_PROTOCHG)) { 
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] key configue changed.", wscfg.wsname);
            clean_webserver(wb);
            fulbak = 1;
        }

        ret = protocol_connect(wb->protocol, wscfg.host, wscfg.prtcl_port, wscfg.username, 
                wscfg.password);
        if (ret != 0) {
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "failed to connect to website [%s] (host is [%s])", 
                wscfg.wsname, wscfg.host);
            webtamper_sleep(1);
            wb->conect_status = 0;
            continue;
        } 

        wb->conect_status = 1;

        /* 获取服务器文件总数 */
        if (!wb->totalnum) {
            ret = count_file_total_num(wb->protocol, wb, &wscfg, wb->dirtree, wscfg.server_root, 
                    wb->local_root, DEFAULT_DEPTH);
            if (ret != 0) {
                wb->totalnum = 0;
            }
        }

        if (!wscfg.enable) {  /* 暂停防篡改 */
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] disable.", wscfg.wsname);
            wb->conect_status = 0;
            protocol_disconnect(wb->protocol);
            while (sem_wait(&wb->monitor_wait) == -1 && errno == EINTR) {
                continue;
            }
            
            incbak = 1;
            continue;
        } else if (wscfg.enable && incbak && !fulbak) {  /* 暂停后重新开启文件增量备份 */
            download_mark(wb->markfile, "0");

            pthread_mutex_lock(&wb->wbmutex);
            svn_del_all_record(wb->svn);
            svn_del_all_record(wb->man_restore);

            /* 获取增量信息 */ 
            compare_file(wb->protocol, wb, &wscfg, wb->dirtree, wscfg.server_root, wb->local_root, 
                wscfg.depth);
            pthread_mutex_unlock(&wb->wbmutex);

            /* 增量备份 */
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] increase download start.", wscfg.wsname);
            ret = inc_download_file(wb->protocol, wb, wb->svn, wb->local_root, wscfg.server_root);
            if (ret == ERROR_EXCEED_TOTALDISKSIZE) {
                /* TODO: 邮件警告 */
                pthread_mutex_lock(&wb->wbmutex);
                wb->cfg.enable = 0;
                pthread_mutex_unlock(&wb->wbmutex);
                TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] increase download failed.", wscfg.wsname);
                goto disconnect;
            }
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] increase download end.", wscfg.wsname);
            pthread_mutex_lock(&wb->wbmutex);
            svn_del_all_record(wb->svn);
            svn_del_all_record(wb->man_restore);
            pthread_mutex_unlock(&wb->wbmutex);

            incbak = 0;
            wb->isbackuped = 1;
            download_mark(wb->markfile, "1");
        }

        /* 文件全额备份 */
        if (fulbak && !wb->isbackuped) {
            /* 下载文件 */
            download_mark(wb->markfile, "0");
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] full download start.", wscfg.wsname);
            ret = ful_download_file(wb->protocol, wb, &wscfg, wb->dirtree, wscfg.server_root, 
                    wb->local_root, wscfg.depth);
            if (ret == ERROR_EXCEED_TOTALDISKSIZE) {
                pthread_mutex_lock(&wb->wbmutex);
                wb->cfg.enable = 0;
                pthread_mutex_unlock(&wb->wbmutex);
                TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] full download failed.", wscfg.wsname);
                goto disconnect;
            }
            TAMPER_LOG_WRITE(PE_LOG_DEBUG, "web server [%s] full download end.", wscfg.wsname);
            wb->isbackuped = 1;
            download_mark(wb->markfile, "1");
        } 
        
        /* 轮询检查 */
        root_count = 0;
        other_count = 0;
        while (wb->cfg.enable) {
            webtamper_sleep(1);

            /* 检测配置是否更改 */
            if (root_count % 5) {
                pthread_mutex_lock(&list_mutex);
                cfg_ret = cheak_cfg(&wscfg, wb);
                pthread_mutex_unlock(&list_mutex);            
                if (cfg_ret != CFG_STATUS_UNCHANGED) {
                    goto disconnect;
                }
            }
            
            root_count++;
            other_count++;
            start_time = apr_time_sec(apr_time_now());
            if (other_count == wscfg.other_interval) {
                pthread_mutex_lock(&wb->wbmutex);
                compare_file(wb->protocol, wb, &wscfg, wb->dirtree, wscfg.server_root, wb->local_root, 
                    wscfg.depth);
                pthread_mutex_unlock(&wb->wbmutex);
                break;
            }

            if (root_count == wscfg.root_interval) {
                pthread_mutex_lock(&wb->wbmutex);
                compare_file(wb->protocol, wb, &wscfg, wb->dirtree, wscfg.server_root, wb->local_root, 
                    1);
                pthread_mutex_unlock(&wb->wbmutex);
                root_count = 0;
            }    
            end_time = apr_time_sec(apr_time_now());
            delta_time = end_time - start_time;
            root_count += delta_time;
            other_count += delta_time;

            /* 网站恢复 */
            if (wscfg.isautorestore) {   
                /* 自动恢复 */
                pthread_mutex_lock(&wb->wbmutex);
                webtamper_log(wscfg.wsname, wscfg.host, "check", wb->svn, wb->local_root, wscfg.server_root);
                auto_restore_file(wb, &wscfg);
                pthread_mutex_unlock(&wb->wbmutex);
            } else {                       
                /* 手动恢复 */
                pthread_mutex_lock(&wb->wbmutex);
                webtamper_log(wscfg.wsname, wscfg.host, "check", wb->svn, wb->local_root, wscfg.server_root);
                man_restore_file(wb, &wscfg);
                pthread_mutex_unlock(&wb->wbmutex);
            }
        }

        /* 网站恢复 */
        if (wscfg.isautorestore) {   
            /* 自动恢复 */
            pthread_mutex_lock(&wb->wbmutex);
            webtamper_log(wscfg.wsname, wscfg.host, "check", wb->svn, wb->local_root, wscfg.server_root);
            auto_restore_file(wb, &wscfg);
            pthread_mutex_unlock(&wb->wbmutex);
        } else {                       
            /* 手动恢复 */
            pthread_mutex_lock(&wb->wbmutex);
            webtamper_log(wscfg.wsname, wscfg.host, "check", wb->svn, wb->local_root, wscfg.server_root);
            man_restore_file(wb, &wscfg);
            pthread_mutex_unlock(&wb->wbmutex);
        }
        
disconnect:
        protocol_disconnect(wb->protocol);
    }
    protocol_uninit(wb->protocol);

    wb->running = 0;

    TAMPER_LOG_WRITE(PE_LOG_FATAL, "web server [%s] exit.", wb->cfg.wsname);

    return NULL;
}

