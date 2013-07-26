/*
 * $Id: tree.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#ifndef _TREE_H_
#define _TREE_H_

#include <stdlib.h>
#include "list.h"
#include "util.h"

#define TYPE_UNTOUCHED 0
#define TYPE_TOUCHED   1

typedef struct directory_s {
    struct directory_s *parent;     
    struct directory_s *firstchild;

    struct list_head brother;
    char *name;
    int  isfile;

    /* 文件属性 */
    unsigned long long filesize;                                /* 文件属性 */
    unsigned long uid, gid;                                     /* 用户ID， 组ID */
    unsigned long permissions;                                  /* 文件权限、文件类型 */
    unsigned long atime, mtime;                                 /* 文件访问时间、 文件修改时间 */
    unsigned char md5_value_unaligned[MD5_BYTES + MD5_ALIGN];   /* 文件md5值 */
    unsigned char *md5_value;

    int  touched;
} directory_t;

/**
 * dir_add_node -  添加节点
 * @param parent: 父节点
 * @param node: 子节点
 *
 * 在父节点上添加子节点
 *
 * @returns
 *     成功: 返回0
 *     失败: 返回-1
 */
extern int dir_add_node(directory_t *parent, directory_t *node);

/**
 * dir_walk_tree -  遍历目录树
 * @param dir: 目录根节点
 *
 * 销毁整棵目录树
 *
 * @returns
 *     成功: 返回0
 *     成功: 返回-1
 */
extern int dir_walk_tree(directory_t *dir);

/**
 * dir_get_local_path -  获取文件所对应的磁盘路径
 * @param node: 节点
 * @param path: 路径缓冲区
 * @param pathlen: 路径缓冲区长度
 *
 * 获取文件所对应的磁盘路径
 *
 * @returns
 *     成功: 返回0
 *     成功: 返回-1
 */
extern int dir_get_local_path(directory_t *node, char *path, int pathlen);

/**
 * dir_cmp_fun1 -  哈希冲突比较算法
 * @param data1: 比较内容1
 * @param data2: 比较内容2
 *
 * 哈希冲突比较算法
 *
 * @returns
 *    返回比较结果，相同返回1，不同返回0
 */
extern int dir_cmp_fun1(void *data1, void *data2);

/**
 * dir_cmp_fun2 -  哈希冲突比较算法
 * @param data1: 比较内容1
 * @param data2: 比较内容2
 *
 * 哈希冲突比较算法
 *
 * @returns
 *    返回比较结果，相同返回1，不同返回0
 */
extern int dir_cmp_fun2(void *data1, void *data2);

/**
 * dir_destroy_tree -  销毁整棵目录树
 * @param dir: 目录树根节点
 *
 * 销毁整棵目录树
 *
 * @returns
 *     成功: 返回0
 *     成功: 返回-1
 */
extern int dir_destroy_tree(directory_t *dir);

/**
 * dir_get_parent_node -  获取文件父节点地址
 * @param root: 根节点
 * @param path: 文件路径
 * @param node_type: 节点类型
 *
 * 获取文件父节点地址
 *
 * @returns
 *     成功: 返回文件父节点地址
 *     失败: NULL
 */
extern directory_t *dir_get_parent_node(directory_t *root, char *path, int node_type);

/**
 * dir_get_self_node -  获取文件节点地址
 * @param root: 根节点
 * @param path: 文件路径
 * @param node_type: 节点类型
 *
 * 获取文件节点地址
 *
 * @returns
 *     成功: 返回文件节点地址
 *     失败: NULL
 */
extern directory_t *dir_get_self_node(directory_t *root, char *name, int node_type);

/**
 * dir_update_node -  更新节点内容
 * @param node: 节点
 * @param fileinfo: 节点更新内容
 *
 * 更新节点内容
 *
 * @returns
 *     成功: 返回0
 *     成功: 返回-1
 */
extern int dir_update_node(directory_t *node, file_t *fileinfo);

/**
 * dir_del_node -  删除自身及其子节点
 * @param node: 节点
 *
 * 删除自身及其子节点
 *
 * @returns
 *     成功: 返回0
 *     成功: 返回-1
 */
extern int dir_del_node(directory_t *node);

#endif

