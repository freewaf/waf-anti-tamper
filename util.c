/*
 * $Id: util.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <string.h>
#include <pthread.h>
#include <dirent.h>
#include <apr_strings.h>
#include "print.h"
#include "list.h"
#include "core.h"
#include "tree.h"
#include "hash.h"
#include "tamperlog.h"
#include "log.h"

#define SQL_LEN   128
#define RECONNECT_NUM 3

/**
 * add_lastfilename -  添加文件名
 * @param path: 文件路径
 * @param file: 文件名
 *
 * 添加文件名
 */
void add_lastfilename(char *path, char *file)
{
    strcat(path, file);
}

/**
 * del_lastfilename -  删除文件名
 * @param path: 文件路径
 * @param file: 文件名
 *
 * 删除文件名
 */
void del_lastfilename(char *path)
{
    char *p;
    p = strrchr(path, '/');
    if (p) {
        *(p + 1) = '\0';
    }
}

/**
 * add_lastdirname -  添加目录名
 * @param path: 文件路径
 * @param file: 目录名
 *
 * 添加目录名
 */
void add_lastdirname(char *path, char *dir)
{
    strcat(path, dir);
    strcat(path, "/");
}

/**
 * del_lastdirname -  删除目录名
 * @param path: 文件路径
 * @param file: 目录名
 *
 * 删除目录名
 */
void del_lastdirname(char *path) 
{
    char *p;
    p = strrchr(path, '/');
    *p = '\0';
    p = strrchr(path, '/');
    if (p) {
        *(p + 1) = '\0';
    }
}

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
void *find_webserver(struct list_head *webserver_listhead, char *wsname)
{
    struct list_head *pos;
    webserver_t *wb;
    
    list_for_each(pos, webserver_listhead) {
        wb = list_entry(pos, webserver_t, list);
        if (wb && !strcmp(wb->cfg.wsname, wsname)) {
            return wb;
        }
    }

    return NULL;
}

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
int should_webserver_run(void *wbtmp)
{
    webserver_t *wb;

    if (wbtmp == NULL) {
        return 0;
    }

    wb = (webserver_t *)wbtmp;
    if (wb->cfg.prtcl_name[0] == '\0'
            || wb->cfg.host[0] == '\0'
            || wb->cfg.username[0] == '\0'
            || wb->cfg.password[0] == '\0'
            || wb->cfg.server_root[0] == '\0'
            /*|| wb->cfg.enable == 0*/) {
        return 0;
    }

    return 1;
}

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
int prepare_webserver(void *wbtmp)
{
    webserver_t *wb;
    int tmp_len;

    wb = (webserver_t *)wbtmp;

    if (!strcmp(wb->cfg.prtcl_name, "sftp")) {
        wb->protocol = protocol_sftp_create();
        if (wb->protocol == NULL) {
            return -1;
        }
    }
  
    /* 初始化目录树 */
    wb->dirtree = (directory_t *)malloc(sizeof(directory_t));
    if (wb->dirtree == NULL) {
        free(wb->change_root);
        free(wb->local_root);
        return -1;
    }
    memset(wb->dirtree, 0, sizeof(directory_t));
    wb->dirtree->name = wb->local_root;

    /* 初始化目录哈希表 */
    wb->dirhash = hash_create(hash_key_fun, dir_cmp_fun1);
    if (wb->dirhash == NULL) {
        free(wb->change_root);
        free(wb->local_root);
        free(wb->dirtree);
        return -1;   
    }

    /* 初始化svn */
    wb->svn = svn_init();
    if (wb->svn == NULL) {
        free(wb->change_root);
        free(wb->local_root);
        free(wb->dirtree);
        hash_destroy(wb->dirhash, NULL);
        return -1;
    }

    /* 初始化svn */
    wb->man_restore = svn_init(); 
    if (wb->man_restore == NULL) {
        free(wb->change_root);
        free(wb->local_root);
        free(wb->dirtree);
        svn_uninit(wb->svn);
        hash_destroy(wb->dirhash, NULL);
        return -1;
    }

    wb->man_reserve = svn_init(); 
    if (wb->man_reserve == NULL) {
        free(wb->change_root);
        free(wb->local_root);
        free(wb->dirtree);
        svn_uninit(wb->svn);
        svn_uninit(wb->man_restore);
        hash_destroy(wb->dirhash, NULL);
        return -1;
    }

    tmp_len = strlen(BACKUP_ROOT) + strlen(wb->cfg.wsname) + strlen("mark") + 2;
    wb->markfile = (char *)malloc(tmp_len);
    if (wb->markfile == NULL) {
        free(wb->change_root);
        free(wb->local_root);
        free(wb->dirtree);
        svn_uninit(wb->svn);
        svn_uninit(wb->man_restore);
        svn_uninit(wb->man_reserve);
        hash_destroy(wb->dirhash, NULL);
        return -1;
    }
    sprintf(wb->markfile, "%s%s/%s", BACKUP_ROOT, wb->cfg.wsname, "mark");

    wb->isbackuped = 0;

    pthread_mutex_init(&wb->wbmutex, NULL);
    sem_init(&wb->monitor_wait, 0, 0);
    sem_init(&wb->destroy_wait, 0, 0);

    return 0;
}

/**
 * clean_webserver -  清除防篡改服务器内容
 * @param wbtmp: 防篡改服务器
 *
 * 清除防篡改服务器内容
 */
void clean_webserver(void *wbtmp)
{            
    if (wbtmp == NULL) {
        return ;
    }
  
    webserver_t *wb = (webserver_t *)wbtmp;
    
    delete_diskfiles(wb->local_root);
    delete_diskfiles(wb->change_root);
    dir_destroy_tree(wb->dirtree);
    hash_clean(wb->dirhash, NULL);
    svn_del_all_record(wb->svn);
    svn_del_all_record(wb->man_restore);
    svn_del_all_record(wb->man_reserve);
    wb->backupnum = 0;
    wb->backupsize = 0;
    wb->changednum = 0;
            
    wb->isbackuped = 0;
}

/**
 * destroy_webserver -  销毁防篡改服务器
 * @param wbtmp: 防篡改服务器
 *
 * 销毁防篡改服务器
 */
void destroy_webserver(void *wbtmp)
{       
    char rootpath[MAX_FILENAME_LEN];

    if (wbtmp == NULL) {
        return ;
    }
  
    webserver_t *wb = (webserver_t *)wbtmp;

    pthread_mutex_lock(&list_mutex);
    list_del(&wb->list);
    pthread_mutex_unlock(&list_mutex);
    
    if (!strcmp(wb->protocol->protocol_name, "sftp")) {
        protocol_sftp_destroy(wb->protocol);
    }

    snprintf(rootpath, MAX_FILENAME_LEN, "%s%s/", BACKUP_ROOT, wb->cfg.wsname);
    delete_diskdir(rootpath);
    free(wb->local_root);
    free(wb->change_root);
    free(wb->markfile);
      
    /* 清除目录树 */
    dir_destroy_tree(wb->dirtree);   

    /* 清除哈希表 */
    hash_destroy(wb->dirhash, NULL);
    
    /* 清除篡改追踪记录 */
    svn_del_all_record(wb->svn);
    svn_del_all_record(wb->man_restore);
    svn_del_all_record(wb->man_reserve);

    pthread_mutex_destroy(&wb->wbmutex);
    sem_destroy(&wb->monitor_wait);
    sem_destroy(&wb->destroy_wait);
    
    free(wb); 
    wb = NULL;
}

/**
 * cfg_copy -  拷贝配置
 * @param dst: 目的配置
 * @param dst: 源配置
 *
 * @returns
 *     配置修改: 返回CHANGED
 *     配置未修改 返回UNCHANGED
 */
int cfg_copy(char *dst, char *src)
{
    if (dst[0] == '\0' || strcmp(dst, src)) {
        strcpy(dst, src);
        return CHANGED;
    }

    return UNCHANGED;
}

/**
 * cfg_copy -  拷贝配置
 * @param dst: 目的配置
 * @param dst: 源配置
 *
 * @returns
 *     配置修改: 返回CHANGED
 *     配置未修改 返回UNCHANGED
 */
int cfg_check(char *dst, char *src)
{
    if (dst[0] == '\0' || strcmp(dst, src)) {
        return CHANGED;
    }

    return UNCHANGED;
}

/**
 * delete_diskfiles -  删除目录下的文件
 * @param path: 目录路径
 *
 * 删除目录下的文件不包括该目录
 */
void delete_diskfiles(char *path)
{
    int ret;    
    char cmd[MAX_PATH_LEN] = {0};

    if (path == NULL) {        
        return;    
    }    

    ret = snprintf(cmd, MAX_PATH_LEN, "rm -rf %s*", path);    
    if (ret > 0) {        
        system(cmd);    
    }
}

/**
 * delete_diskdir -  删除目录及其文件
 * @param path: 目录路径
 *
 * 删除目录下的文件不包括该目录
 */
void delete_diskdir(char *path)
{
    if (path == NULL) {
        return;    
    }    

    delete_diskfiles(path);    
    (void)rmdir(path);
}

/**
 * webtamper_sleep -  休眠
 * @param time: 休眠时间
 *
 * 休眠
 */
void webtamper_sleep(long time) 
{
    struct timeval tv;
    tv.tv_usec = 0;
    tv.tv_sec = time;
    select(0, NULL, NULL, NULL, &tv);
}

/**
 * get_info -  获取文件属性
 * @param name: 文件名
 * @param statbuf: 竞争条件
 * @param dir: 间隔时间
 *
 * @returns
 *     成功: 返回0
 *     失败: 返回-1
 */
static int get_info(char *fulname, char *name, struct stat *statbuf, directory_t *dir)
{
    dir->name = (char *)malloc(strlen(name) + strlen("/") + 1);  /* 内存需要回退 */
    if (dir->name == NULL) {
        return -1; 
    }
    
    strcpy(dir->name, name);
    if (S_ISDIR(statbuf->st_mode) && !strchr(dir->name, '/')) {
        strcat(dir->name, "/");
    }

    dir->isfile = !S_ISDIR(statbuf->st_mode);
    dir->mtime = statbuf->st_mtime;
    dir->atime = statbuf->st_atime;
    dir->gid = statbuf->st_gid;
    dir->uid = statbuf->st_uid;
    dir->permissions = statbuf->st_mode;

    if (dir->isfile) {
        dir->filesize = statbuf->st_size;
        dir->md5_value = md5_value_align(dir->md5_value_unaligned, MD5_ALIGN);
        md5_generate_value(fulname, dir->md5_value);
    }

    return 0;
}

/**
 * build_hashtree -  创建哈希表和目录树，初始化防篡改服务器使用
 * @param mutex: 目录位置
 * @param root: 目录根节点
 * @param hash: 哈希表
 *
 * 创建哈希表和目录树，初始化防篡改服务器使用
 */
void build_hashtree(char *path, void *root, struct hash *hash)
{
    DIR *dp;
    struct dirent *entry;  
    struct stat statbuf;  
    directory_t *node;
    int ret;
    char dirdp[MAX_PATH_LEN] = {0};
    directory_t *dir;

    dir = (directory_t *)root;
    
    strcpy(dirdp, path);
    
    if((dp = opendir(path)) == NULL) {  
        TAMPER_LOG_WRITE(PE_LOG_INFO, "can not open directory: %s\n", path);
        return;
    }  
    
    chdir(path);
    while((entry = readdir(dp)) != NULL) {
        lstat(entry->d_name, &statbuf);
        if(S_ISDIR(statbuf.st_mode)) {
            if(strcmp(".", entry->d_name) == 0 || strcmp("..", entry->d_name) == 0) {
                continue;  
            }
            
            /* 创建目录树节点 */
            node = (directory_t *)malloc(sizeof(directory_t));
            if (node == NULL) {
                return;
            }
            memset(node, 0, sizeof(directory_t));

            /* 获取文件夹属性 */
            add_lastdirname(dirdp, entry->d_name);
            ret = get_info(dirdp, entry->d_name, &statbuf, node);
            if (ret == -1) {
                free(node);
                return;
            }

            /* 插入节点 */
            ret = dir_add_node(dir, node);
            if (ret == -1) {
                free(node->name);
                free(node);
                return;
            }
            
            hash_set(hash, dirdp, node);
            build_hashtree(dirdp, node, hash);  
            del_lastdirname(dirdp);
        } else {
            /* 创建目录树节点 */
            node = (directory_t *)malloc(sizeof(directory_t));
            if (node == NULL) {
                return;
            }
            memset(node, 0, sizeof(directory_t));
            
            /* 获取文件属性 */
            add_lastfilename(dirdp, entry->d_name);
            ret = get_info(dirdp, entry->d_name, &statbuf, node);
            if (ret == -1) {
                free(node);
                return;
            }

            /* 插入节点 */
            ret = dir_add_node(dir, node);
            if (ret == -1) {
                free(node->name);
                free(node);
                return;
            }
        
            /* 插入哈希表 */
            hash_set(hash, dirdp, node);
            del_lastfilename(dirdp);
        }
    }  
    chdir("..");  
    
    closedir(dp); 
}

/**
 * interval_check -  轮询间隔
 * @param mutex: 互斥量
 * @param cond: 竞争条件
 * @param interval_time: 间隔时间
 *
 * 下载成功与否标志
 */
int interval_check(pthread_mutex_t *mutex, pthread_cond_t *cond, int interval_time)
{
    int  condret;
    struct timespec timeout;

    timeout.tv_sec = time(0) + interval_time;
    timeout.tv_nsec = 0;

    pthread_mutex_lock(mutex);
    condret = pthread_cond_timedwait(cond, mutex, &timeout);
    pthread_mutex_unlock(mutex);

    return condret;
}

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
int download_mark(const char *filename, const char *mark)
{
    FILE *fp;
    
    fp = fopen(filename, "w");
    if (fp == NULL) {
        return -1;
    }

    fputs(mark, fp);

    fclose(fp);

    return 0;
}

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
int is_download_success(const char *filename)
{
    FILE *fp;
    char mark[2] = {0};    /* 文件中只需提取1个字符 */
    
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return 0;
    }
    fgets(mark, 2, fp);    /* 文件中只需提取1个字符 */
    fclose(fp);

    return !(strcmp(mark, "1"));
}

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
int make_previous_dir(char *path)
{
    char cmd[MAX_PATH_LEN] = {0};
    char *p;    

    p = strrchr(path, '/');
    if (p != NULL) {
        snprintf(cmd, p - path + 12, "mkdir -p '%s", path);
        strcat(cmd, "'");
        system(cmd);
        return 0;
    }

    return -1;
}

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
void webtamper_log(char *wsname, char *host, char *action, svn_t *svn, char *local_root, 
        char *server_root)
{
    struct list_head *pos;
    struct list_head *tmppos;
    svn_node_t *tmp;
    char filename[MAX_PATH_LEN] = {0};

    list_for_each_safe(pos, tmppos, &svn->add_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        sprintf(filename, "%s%s", server_root ,tmp->filename + strlen(local_root));
        if (!tmp->isstored && !strcmp(action, "check")) {
            log_write(wsname, host, action, tmp->detecttime, tmp->tampertime, tmp->restoretime, svn->last_version, tmp->action, 
                filename);

            syslog_print_info("WAF", "WEBTAMPER","File [%s] has been [%s] on website[%s] (host is [%s])\n",
                    filename, "Added", wsname, host);

            tmp->isstored = !tmp->isstored;
        }

        if (!strcmp(action, "arestore") || !strcmp(action, "mrestore")) {
            log_write(wsname, host, action, tmp->detecttime, tmp->tampertime, tmp->restoretime, svn->last_version, tmp->action, 
                filename);

            syslog_print_info("WAF", "WEBTAMPER","File [%s] has been %s successfully on website[%s]"
                " (host is [%s])\n", filename, action, wsname, host);
        }
    }

    list_for_each_safe(pos, tmppos, &svn->update_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        sprintf(filename, "%s%s", server_root ,tmp->filename + strlen(local_root));
        if (!tmp->isstored && !strcmp(action, "check")) {
            log_write(wsname, host, action, tmp->detecttime, tmp->tampertime, tmp->restoretime, svn->last_version, tmp->action, 
                filename);

            syslog_print_info("WAF", "WEBTAMPER","File [%s] has been [%s] on website[%s] (host is [%s])\n",
                    filename, "Modified", wsname, host);

            tmp->isstored = !tmp->isstored;
        }

        if (!strcmp(action, "arestore") || !strcmp(action, "mrestore")) {
            log_write(wsname, host, action, tmp->detecttime, tmp->tampertime, tmp->restoretime, svn->last_version, tmp->action, 
                filename);

            syslog_print_info("WAF", "WEBTAMPER","File [%s] has been %s successfully on website[%s]"
                " (host is [%s])\n", filename, action, wsname, host);
        }
    }

    list_for_each_safe(pos, tmppos, &svn->delete_files.brother) {
        tmp = list_entry(pos, svn_node_t, brother);
        sprintf(filename, "%s%s", server_root ,tmp->filename + strlen(local_root));
        if (!tmp->isstored && !strcmp(action, "check")) {
            log_write(wsname, host, action, tmp->detecttime, tmp->tampertime, tmp->restoretime, svn->last_version, tmp->action, filename);

            syslog_print_info("WAF", "WEBTAMPER","File [%s] has been [%s] on website[%s] (host is [%s])\n",
                filename, "Deleted", wsname, host);

            tmp->isstored = !tmp->isstored;
        }

        if (!strcmp(action, "arestore") || !strcmp(action, "mrestore")) {
            log_write(wsname, host, action, tmp->detecttime, tmp->tampertime, tmp->restoretime, svn->last_version, tmp->action, filename);

            syslog_print_info("WAF", "WEBTAMPER","File [%s] has been %s successfully on website[%s]"
                " (host is [%s])\n", filename, action, wsname, host);
        }
    }
}

int log_send(char *buf, int is_buffer)
{
    int rv, i;
    
    if (!buf) {
        return -1;
    }

    i = 0;
    rv = pe_log_client_write(g_log_client, is_buffer, buf, strlen(buf));
    if (rv < 0) {
        for (i = 0; i < RECONNECT_NUM; ++i) {
            if (!pe_log_client_check_conn(g_log_client)) {
                    rv = pe_log_client_connect(g_log_client);
                    if (rv != 0) {
                        continue;
                    }
                }

            rv = pe_log_client_write(g_log_client, is_buffer, buf, strlen(buf));
            break ;
        }
    }

    if (i == RECONNECT_NUM) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "reconnect failure %d", rv);
    }
    
    return rv;
}

void send_detect_log(char *ip)
{
#define SQL_STATEMENT_LEN 10000
    int rv;
    char sql_statement[SQL_STATEMENT_LEN] = {0};
 
    snprintf(sql_statement, SQL_STATEMENT_LEN, "insert into tamper_log_temp_table values(UNIX_TIMESTAMP(), '%s');", ip);

    rv = log_send(sql_statement, 0);
    if (rv < 0) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "send tamper temp record to log server failed.");
    }
}

unsigned long long get_tamper_total_sizes(char *backup_path)
{
    struct statfs diskInfo;
    int ret;
    
    ret = statfs(backup_path, &diskInfo);
    if (ret == 0) {
        return (unsigned long long)diskInfo.f_bsize * (unsigned long long)diskInfo.f_blocks;
    } else {
        return 0;
    }
}

