/*
 * $Id: core.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#ifndef _CORE_H_
#define _CORE_H_

#include <pe_log_client.h>
#include <apr_pools.h>
#include <apr_time.h>
#include <apr_dbd.h>
#include <pthread.h>
#include <semaphore.h>
#include "apr_global_mutex.h"
#include "protocol_sftp.h"
#include "list.h"
#include "svn.h"
#include "md5.h"
#include "tree.h"

/* 默认前台运行 */
#define TEMPER_BACKGROUND_RUN    1

#define ERROR_MALLOC_FAILED      -1
#define CHANGED                  1
#define UNCHANGED                2

/* 配置默认长度 */
#define MAX_WSNAME_LEN           16
#define MAX_PRTCLNAME_LEN        16
#define MAX_DESCRIPTION_LEN      255
#define MAX_EMAIL_LEN            32
#define MAX_HOST_LEN             32
#define MAX_SERVERROOT_LEN       255
#define MAX_USERNAME_LEN         16
#define MAX_PASSWORD_LEN         64
#define MAX_NOTSUFFIX_LEN        255
#define MAX_CLI_PROMPT_LEN       32
#define MAX_SUFFIX_LEN           32

#define DEBUG_ALL                (1)
#define DEBUG_CORE               (1 << 1)
#define DEBUG_COMM               (1 << 2)

#define LOG_CACHE_TIME              60000000
#define LOG_CACHE_NUM               1000
#define LOG_SERVER_PATH             "/tmp/pe_log_server.uds"

extern struct list_head webserver_listhead;
extern pthread_mutex_t list_mutex;
extern unsigned long long total_disksize;
extern unsigned long long left_disksize;
extern pe_log_client_t *g_log_client;
extern apr_pool_t *g_global_pool;
extern const apr_dbd_driver_t *ap_logdb_driver;
extern apr_dbd_t *ap_logdb_handle;
extern char *g_open_db_parm;

typedef struct admin_log_s {
    apr_time_t time;
    char *ip;
    char *admin_name;
    char *tty;
    char *action;
} admin_log_t;

typedef struct suffix_s {
    struct list_head list;
    char suffix[MAX_SUFFIX_LEN];
} suffix_t;

typedef struct webserver_cfg_s {
    /* 配置属性 */
    char wsname[MAX_WSNAME_LEN];             /* 网页防篡改名称 */
    char description[MAX_DESCRIPTION_LEN];   /* 网页防篡改描述 */
    char email[MAX_EMAIL_LEN];               /* 出错警告邮件地址 */
    char prtcl_name[MAX_PRTCLNAME_LEN];      /* 协议名 */
    int  prtcl_port;                         /* 协议端口 */
    char host[MAX_HOST_LEN];                 /* 后台服务器地址IP 或 域名*/
    char server_root[MAX_SERVERROOT_LEN];    /* 网站根目录 */
    char username[MAX_USERNAME_LEN];         /* 用户名 */
    char password[MAX_PASSWORD_LEN];         /* 密码 */
    int isautorestore;                       /* 是否自动恢复 */
    int enable;                              /* 网页防篡改功能是否开启 */
    int depth;                               /* 文件保护深度 */
    int maxfilesize;                         /* 保护文件的最大尺寸 */  
    struct list_head suffix_head;            /* 不进行下载的后缀 */
    int root_interval;                       /* 根目录轮询时间  */
    int other_interval;                      /* 其他目录轮询时间 */
    int sysloglevel;                         /* 系统日志等级 */
    unsigned long long disksize;             /* 配置该web服务器的磁盘大小,单位为MB */
    int debug;                               /* debug调试开关 */
    int destroywb;                           /* 销毁 */
    int iscomit;
} webserver_cfg_t;

typedef struct webserver_s {
    struct list_head list;

    /* 配置参数  */
    webserver_cfg_t cfg;

    /* 管理变量 */
    protocol_data_t *protocol;               /* 使用协议包 */
    int running;                             /* 网页防篡改线程是否创建 */
    int isbackuped;                          /* 是否已经备份 */
    int conect_status;                       /* 连接状态 1代表连接 0代表未连接 */
    char *local_root;                        /* WAF上存储的位置 */
    char *change_root;                       /* 手动恢复模式下文件暂存磁盘位置 */
    char *markfile;                          /* 完全备份标记文件 */

    /* 显示变量 */
    unsigned int totalnum;                   /* 文件文件总数 */
    unsigned int backupnum;                  /* 备份文件总数 */
    unsigned long long backupsize;           /* 备份文件大小 */
    unsigned int changednum;                 /* 被篡改的文件数 */
    int suffix_changed;

    /* 文件管理 */
    directory_t *dirtree;                    /* 目录树 */
    struct hash *dirhash;                    /* 哈希表 */
    svn_t *svn;                              /* 篡改追踪 */
    svn_t *man_restore;                      /* 手动恢复缓存 */
    svn_t *man_reserve;                      /* 手动保留缓存 */
    
    pthread_mutex_t wbmutex;                 /* 单台防篡改互斥 */
    sem_t monitor_wait;                      /* 篡改监控信号量 */
    sem_t destroy_wait;                      /* 防篡改删除信号量 */
} webserver_t;

extern void *worker_thread(void *arg);
extern int log_send(char *buf, int is_buffer);

#endif

