/*
 * $Id: util.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#ifndef _UTIL_H_
#define _UTIL_H_

#include "list.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/vfs.h>
#include "md5.h"
#include "svn.h"
#include "apr_pools.h"

#define MAX_BUF_LEN              256
#define MAX_FILENAME_LEN         256
#define MAX_PATH_LEN             4097
#define MD5_BYTES                DIGEST_BIN_BYTES
#define MD5_ALIGN                DIGEST_ALIGN
#define TAMPER_VERSION           "1.0.0"
#define TAMPER_BUILD             "437"
#define TAMPER_RELEASE           "7098"

#define BACKUP_ROOT              "/var/tamper/"
#define WEBTAMPER_FLOCK_PATH     "/tmp/webtamper.flock"

#define NODE_DIR  0
#define NODE_FILE 1

typedef struct file_s {
    char filename[MAX_FILENAME_LEN];
    unsigned long long filesize;
    unsigned long uid, gid;
    unsigned long permissions;
    unsigned long atime, mtime;
} file_t;

/**
 * add_lastfilename -  添加文件名
 * @param path: 文件路径
 * @param file: 文件名
 *
 * 添加文件名
 */
extern void add_lastfilename(char *path, char *file);

/**
 * del_lastfilename -  删除文件名
 * @param path: 文件路径
 * @param file: 文件名
 *
 * 删除文件名
 */
extern void del_lastfilename(char *path);

/**
 * add_lastdirname -  添加目录名
 * @param path: 文件路径
 * @param file: 目录名
 *
 * 添加目录名
 */
extern void add_lastdirname(char *path, char *dir);

/**
 * del_lastdirname -  删除目录名
 * @param path: 文件路径
 * @param file: 目录名
 *
 * 删除目录名
 */
extern void del_lastdirname(char *path);

/**
 * find_webserver -  查找防篡改服务器
 * @param webserver_listhead: 防篡改服务器链表头结点
 * @param wsname: 防篡改服务器名
 *
 * 查找防篡改服务器
 *
 * @returns
 *     成功: 返回防篡改服务结点地址
 *     失败: NULL
 */
extern void *find_webserver(struct list_head *webserver_listhead, char *wsname);

/**
 * destroy_webserver -  销毁防篡改服务器
 * @param wbtmp: 防篡改服务器
 *
 * 销毁防篡改服务器
 */
extern void destroy_webserver(void *wb);

/**
 * add_lastfilename -  判断防篡改服务器是否具备运行条件
 * @param wbtmp: 防篡改服务器
 *
 * 判断防篡改服务器是否具备运行条件
 *
 * @returns
 *     成功: 返回1
 *     失败: 返回0
 */
extern int should_webserver_run(void *wbtmp);

/**
 * prepare_webserver -  初始化防篡改服务器运行条件
 * @param wbtmp: 防篡改服务器
 *
 * 初始化防篡改服务器运行条件
 *
 * @returns
 *     成功: 返回0
 *     失败: 返回-1
 */
extern int prepare_webserver(void *wbtmp);

/**
 * cfg_copy -  拷贝配置
 * @param dst: 目的配置
 * @param dst: 源配置
 *
 * @returns
 *     配置修改: 返回CHANGED
 *     配置未修改 返回UNCHANGED
 */
extern int cfg_copy(char *dst, char *src);

/**
 * cfg_copy -  拷贝配置
 * @param dst: 目的配置
 * @param dst: 源配置
 *
 * @returns
 *     配置修改: 返回CHANGED
 *     配置未修改 返回UNCHANGED
 */
extern int cfg_check(char *dst, char *src);

/**
 * delete_diskfiles -  删除目录下的文件
 * @param path: 目录路径
 *
 * 删除目录下的文件不包括该目录
 */
extern void delete_diskfiles(char *path);

/**
 * delete_diskdir -  删除目录及其文件
 * @param path: 目录路径
 *
 * 删除目录下的文件不包括该目录
 */
extern void delete_diskdir(char *path);

/**
 * webtamper_sleep -  休眠
 * @param time: 休眠时间
 *
 * 休眠
 */
extern void webtamper_sleep(long time);

/**
 * build_hashtree -  创建哈希表和目录树，初始化防篡改服务器使用
 * @param mutex: 目录位置
 * @param root: 目录根节点
 * @param hash: 哈希表
 *
 * 创建哈希表和目录树，初始化防篡改服务器使用
 */
extern void build_hashtree(char *path, void *root, struct hash *hash);

/**
 * clean_webserver -  清除防篡改服务器内容
 * @param wbtmp: 防篡改服务器
 *
 * 清除防篡改服务器内容
 */
extern void clean_webserver(void *wbtmp);

/**
 * interval_check -  轮询间隔
 * @param mutex: 互斥量
 * @param cond: 竞争条件
 * @param interval_time: 间隔时间
 *
 * 下载成功与否标志
 */
extern int interval_check(pthread_mutex_t *mutex, pthread_cond_t *cond, int interval_time);

/**
 * download_mark -  下载成功与否标志
 * @param filename: 标志存储文件名
 * @param mark: 标志，成功为"1",失败为"0"
 *
 * 下载成功与否标志
 *
 * @returns
 *     成功: 返回0
 *     失败: 返回-1
 */
extern int download_mark(const char *filename, const char *mark);

/**
 * is_download_success -  判断文件是否下载成功
 * @param filename: 标志存储文件名
 *
 * 判断文件是否下载成功
 *
 * @returns
 *     成功: 返回1
 *     失败: 返回0
 */
extern int is_download_success(const char *filename);

/**
 * webtamper_log -  篡改日志输出接口
 * @param wsname: 防篡改服务器名称
 * @param host: 防篡改服务器域名或IP
 * @param action: 行动
 * @param svn: 篡改追踪记录
 * @param local_root: 本地根路径
 * @param server_root: 服务器根路径
 *
 * 篡改日志输出接口
 */
extern void webtamper_log(char *wsname, char *host, char *action, svn_t *svn, char *local_root, 
        char *server_root);

/**
 * make_previous_dir -  创建线程目录
 * @param wbtmp: 文件或者文件夹绝对路径
 *
 *  创建线程目录
 *
 * @returns
 *     成功: 返回-1
 *     失败: 返回0
 */
extern int make_previous_dir(char *path);

extern void send_detect_log(char *ip);

extern unsigned long long get_tamper_total_sizes(char *backup_path);

#endif

