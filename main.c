/*
 * $Id: main.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <getopt.h>
#include <sys/vfs.h>
#include "core.h"
#include <pe_log_client.h>
#include <apr_dbd.h>
#include <apr_strings.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include "print.h"
#include "list.h"
#include "util.h"
#include "log.h"
#include "cli_unix.h"
#include "public.h"

#define MYSQL_DRIVER_NAME           "mysql"
#define DB_HOST                     "localhost"
#define DB_USER                     "root"
#define DB_PASS                     "123456"

struct list_head webserver_listhead;         /* 防篡改服务器链表头 */
pthread_mutex_t list_mutex;                  /* 防篡改服务器链表互斥量 */
unsigned long long total_disksize;           /* 剩余磁盘空间 */
unsigned long long left_disksize;            /* 剩余磁盘空间 */
pe_log_client_t *g_log_client;
apr_pool_t *g_global_pool;
const apr_dbd_driver_t *ap_logdb_driver;
apr_dbd_t *ap_logdb_handle;
char *g_open_db_parm;

static apr_status_t pool_cleanup(void *data) 
{
    pe_log_client_t *log_client;

    log_client = (pe_log_client_t *)data;
    
    pe_log_client_destroy(log_client);

    return APR_SUCCESS;
}

static int logdb_init(apr_pool_t *pool)
{
    int rv;

    /* 初始化数据库 */
    rv = apr_dbd_init(pool);
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "apr dbd init failed.");
        return -1;
    }

    rv = apr_dbd_get_driver(pool, MYSQL_DRIVER_NAME, &ap_logdb_driver);
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "get database driver failed.");
        return -1;
    }

    /* 打开数据库 */
    g_open_db_parm = apr_psprintf(pool, "host=%s;user=%s;pass=%s;dbname=%s", 
        DB_HOST, DB_USER, DB_PASS, "waf_db");
    rv = apr_dbd_open(ap_logdb_driver, pool, g_open_db_parm, &ap_logdb_handle);
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "open database waf_db failed.");
        return -1;
    }
    
    return 0;
}

static int lockfile(int fd)
{
    struct flock fl;
    int rc;
    
    fl.l_type = F_WRLCK;
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    
    while ((rc = fcntl(fd, F_SETLK, &fl)) < 0 && errno == EINTR)
        continue;

    return rc;
}

static int check_path(char *lock_file)
{
    char pathname[MAX_PATH_LEN];
    char dir[MAX_PATH_LEN];
    char *ptr, *str;
    int ret;

    strncpy(pathname, lock_file, MAX_PATH_LEN);
    strncpy(dir, "", MAX_PATH_LEN);
    while ((ptr = strstr(pathname, "/")) != NULL) {
        str = ptr + 1;
        ptr[0] = '\0';
        
        strcat(dir, pathname);
        if (strcmp(dir, "") != 0) {
            if (access(dir, F_OK) < 0){
                ret = mkdir(dir, S_IRWXU|S_IRWXG|S_IROTH|S_IXOTH);
                if (ret == -1) {
                    TAMPER_LOG_WRITE(PE_LOG_FATAL, "mkdir failure.");
                    return -1;
                }
            }
        }

        strcat(dir, "/");
        strcpy(pathname, str);
    }
    
    return 0;
}

static int check_process_unique()
{
    int fd;
    int rv;

    rv = check_path(WEBTAMPER_FLOCK_PATH);
    if (rv != 0) {
        return -1;
    }
    
    fd = open(WEBTAMPER_FLOCK_PATH, O_RDWR|O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "create process lock file\"%s\" failed.", WEBTAMPER_FLOCK_PATH);
        return -1;
    }    

    rv = lockfile(fd);
    if (rv < 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "anti-tamper may have been run.");
        return -1;
    }

    return 0;
}

static int log_client_init(apr_pool_t *pool)
{
    int ret;
    
    g_log_client = pe_log_client_create(g_global_pool, LOG_SERVER_PATH, MYSQL_DRIVER_NAME, 
        g_open_db_parm, LOG_CACHE_TIME, LOG_CACHE_NUM);
    
    if (g_log_client == NULL) {      
        return -1;
    }

    ret = pe_log_client_connect(g_log_client);
    if (ret != 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "connect log server failed.");  
    }

    return 0;
}

int main(int argc, char *argv[])
{   
    struct list_head *pos;
    webserver_t *wb;
    int ret;
    pthread_t cliid, workid;
    int c;
    char *const short_options = "v";
    pe_log_t *log_handle;
    pthread_attr_t thread_attr;
    struct option long_options[] = {    
        {"version", 0, NULL, 'v'},    
        {0, 0, 0, 0},
    };     
    char log_filename[1024] = {0};

    if (access(BACKUP_ROOT, F_OK) != 0) {
        ret = mkdir(BACKUP_ROOT, 0777);
        if (ret != 0) {
            return -1;
        }
    }
    
    log_handle = pe_log_create();
    if (log_handle == NULL) {
        return -1;
    }

    strncat(log_filename, ROOT_PATH, 1024);
    strncat(log_filename, "/logs/error_log", 1024);
    ret = pe_log_initialize(log_handle, log_filename, PE_LOG_DEBUG, 1024 * 1024 * 10);
    if (ret != 0) {
        return -1;
    }   
    
    while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        if (c == 'v') {
            msg_printf("Anti-tamper %s Release(%s)\n", TAMPER_VERSION, TAMPER_RELEASE);       
            pe_log_destroy(log_handle);
            return -1;
        } 
    }

    ret = libssh2_init(0);
    if (ret != 0) { 
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "libssh2 initialization failed (%d)\n", ret);
        return -1;
    }
            
#if TEMPER_BACKGROUND_RUN    
    /* 转换为守护进程 */
    ret = daemon(1, 0);
    if (ret != 0) {
        pe_log_destroy(log_handle);
        return -1;
    }  
#endif

    /* 校验进程运行的唯一性 */
    ret = check_process_unique();
    if (ret != 0) {
        pe_log_destroy(log_handle);
        return -1;
    }

    TAMPER_LOG_WRITE(PE_LOG_FATAL, "anti-tamper start.");
    
    /* 初始化内存池 */
    ret = apr_pool_initialize();
    if (APR_SUCCESS != ret) {
        pe_log_destroy(log_handle);
        return -1;
    }

    ret = pthread_attr_init(&thread_attr);
    if (ret != 0) {
        pe_log_destroy(log_handle);
        return -1;  
    }

    ret = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
    if (ret != 0) {
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        return -1; 
    }
    
    ret = apr_pool_create(&g_global_pool, NULL);
    if (ret != APR_SUCCESS || g_global_pool == NULL) {
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        return -1;
    }

    /* 初始化防篡改服务器链表及其互斥量 */
    INIT_LIST_HEAD(&webserver_listhead);     
    pthread_mutex_init(&list_mutex, NULL);

    /* 初始化磁盘剩余大小 */
    total_disksize = get_tamper_total_sizes(BACKUP_ROOT);
    if (total_disksize) {
        left_disksize = total_disksize;
    } else {
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        apr_pool_destroy(g_global_pool);
        return -1;
    }

    ret = logdb_init(g_global_pool);
    if (ret != 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "tamper log client init failed.");
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        apr_pool_destroy(g_global_pool);
        return -1;      
    }

    ret = log_client_init(g_global_pool);
    if (ret != 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "log client init failed.");
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        apr_pool_destroy(g_global_pool);
        return -1; 
    }

    apr_pool_cleanup_register(g_global_pool, g_log_client, pool_cleanup, apr_pool_cleanup_null);

    ret = show_adminlog_init(g_global_pool);
    if (ret != 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "show admin log init failed.");
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        apr_pool_destroy(g_global_pool);
        return -1;   
    }
                 
    /* 创建CLI线程 */
    wb = NULL;
    ret = pthread_create(&cliid, NULL, cli_thread, wb);
    if (ret != 0) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "create cli thread failed.");
        pthread_attr_destroy(&thread_attr);
        pe_log_destroy(log_handle);
        apr_pool_destroy(g_global_pool);
        return -1;
    }

    /* 创建防篡改业务线程 */
    while (1) {
        pthread_mutex_lock(&list_mutex);
        list_for_each(pos, &webserver_listhead) {
            wb = list_entry(pos, webserver_t, list);
            if (wb && should_webserver_run(wb) && !wb->running) {
                /* 创建防篡改线程 */
                ret = pthread_create(&workid, &thread_attr, worker_thread, wb);
                if (ret != 0) {
                    TAMPER_LOG_WRITE(PE_LOG_FATAL, "create tamper worker thread failed.");
                    continue;
                }
                wb->running = 1;
            }
        }
        pthread_mutex_unlock(&list_mutex);
        /* 防止占用过多CPU资源 */
        webtamper_sleep(1);
    }
 
    pthread_join(cliid, NULL);

    /* 清理 */
    pthread_attr_destroy(&thread_attr);
    pthread_mutex_destroy(&list_mutex);
    pe_log_destroy(log_handle);
    apr_pool_destroy(g_global_pool);
    libssh2_exit();
    TAMPER_LOG_WRITE(PE_LOG_FATAL, "anti-tamper exit.");

    return 0;
}

