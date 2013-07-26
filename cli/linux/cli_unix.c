/*
 * $Id: cli_unix.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <pe_log_client.h>
#include <apr_strings.h>
#include <arpa/inet.h>
#include <assert.h>
#include <utmp.h>
#include <syslog.h>
#include "print.h"
#include "cparser.h"
#include "cparser_priv.h"
#include "cparser_token.h"
#include "global_root.h"
#include "cparser_show_tree.h"
#include "cparser_tree.h"
#include "log.h"
#include "apr_dbd.h"
#include "cli_unix.h"
#include "tamperlog.h"
#include "3des.h"
#include "public.h"

#define DEFAULT_CLI_PROMPT              "FreeWAF"
#define PASSWORD_KEY                    "12345678901234567890123456789012"
#define SQL_STATEMENT_LEN               10000
#define COMMAND_LEN_MAX                 128
#define FORMATE_TAMPERLOG_STRING        "%-16s  %-15s  %-11s  %-24s  %s\n"
#define FORMATE_TAMPERLOG_STRING_UTF8   "%-16s  %-15s  %-s  %-24s  %s\n"
#define FORMATE_ADMINLOG_STRING         "%-24s  %-12s  %-15s  %-12s  %-12s  %s\n"

#define UNIT_CONVERT_B_TO_MB(byte_size) (((unsigned long long)byte_size) >> 20)  
#define UNIT_CONVERT_MB_TO_B(mb_size)   (((unsigned long long)mb_size) << 20)
#define UNIT_CONVERT_B_TO_KB(byte_size) (((unsigned long long)byte_size) >> 10) 
#define UNIT_CONVERT_KB_TO_B(kb_size)   (((unsigned long long)kb_size) << 10)

static const char *restore_type[] = {"manual", "auto", NULL};
static const char *monitor_type[] = {"disable", "enable", NULL};
static char g_last_wsname[MAX_WSNAME_LEN] = {0};
static apr_pool_t *g_padminlog;
char g_cli_prompt[MAX_CLI_PROMPT_LEN];

/* 设置网页防篡改默认配置 */
static void uninit_webserver_cfg(webserver_t *wb)
{
    int rv;
    
    char rootpath[MAX_FILENAME_LEN] = {0};
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    apr_dbd_results_t *res;
    apr_pool_t *ptemp;

    pthread_mutex_lock(&list_mutex);
    list_del(&wb->list);
    pthread_mutex_unlock(&list_mutex);
    
    snprintf(rootpath, MAX_FILENAME_LEN, "%s%s/", BACKUP_ROOT, wb->cfg.wsname);
    delete_diskdir(rootpath);
    free(wb->local_root);
    free(wb->change_root);

    apr_pool_create(&ptemp, g_global_pool);
    apr_pool_tag(ptemp, "ptemp");

    res = NULL;
    snprintf(sql_statement, SQL_STATEMENT_LEN, "delete from server_dir_webtamper where server='%s';", wb->cfg.wsname);
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "uninit webserver cfg failure\n");
    }

    apr_pool_destroy(ptemp);
    free(wb);
    wb = NULL;
}

/* 设置网页防篡改默认配置 */
static int init_webserver_cfg(void *wbtmp, char *wsname)
{
    webserver_t *wb;
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    char backuproot[SQL_STATEMENT_LEN] = {0};
    int rv;
    apr_pool_t *ptemp;
    apr_dbd_results_t *res;
    int nrows;
    int chgrootlen;
    
    wb = (webserver_t *)wbtmp;

    strcpy(wb->cfg.wsname, wsname);
    INIT_LIST_HEAD(&(wb->cfg.suffix_head));     
    strcpy(wb->cfg.server_root, DEFAULT_DOCUMENT_ROOT);

    wb->cfg.debug = DEFAULT_DEBUG;
    wb->cfg.depth = DEFAULT_DEPTH;
    wb->cfg.isautorestore = DEFAULT_AUTORESTORE;
    wb->cfg.maxfilesize = UNIT_CONVERT_KB_TO_B(DEFAULT_MAXFILESIZE);
    wb->cfg.root_interval = DEFAULT_ROOT_INTERVAL;
    wb->cfg.other_interval = DEFAULT_OTHER_INTERVAL;
    wb->cfg.enable = DEFAULT_MONITOR;
    wb->cfg.destroywb = 0;
    wb->cfg.iscomit = 0;

    snprintf(backuproot, SQL_STATEMENT_LEN, "%s%s/", BACKUP_ROOT, wsname);
    delete_diskdir(backuproot);
    
    pthread_mutex_lock(&list_mutex);
    if (left_disksize >= UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE)) {
        wb->cfg.disksize = UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE);
    } else {
        wb->cfg.disksize = left_disksize;
    }
    left_disksize -= wb->cfg.disksize;
    pthread_mutex_unlock(&list_mutex);

    /* 创建服务器比较文件夹 */
    chgrootlen = strlen(BACKUP_ROOT) + strlen(wb->cfg.wsname) + 20;
    wb->change_root = (char *)malloc(chgrootlen);
    if (wb->change_root == NULL) {
        return -1;
    }
    snprintf(wb->change_root, chgrootlen, "%s%s/", BACKUP_ROOT, wb->cfg.wsname);
    mkdir(wb->change_root, 0777);
    strcat(wb->change_root, "changed/");
    mkdir(wb->change_root, 0777);

    /* 创建服务器备份文件夹 */
    wb->local_root = (char *)malloc(chgrootlen);
    if (wb->local_root == NULL) {
        free(wb->change_root);
        return -1;
    }
    snprintf(wb->local_root, chgrootlen, "%s%s/backup/", BACKUP_ROOT, wb->cfg.wsname);
    mkdir(wb->local_root, 0777);
    
    /* 发送磁盘信息到日志服务器 */
    apr_pool_create(&ptemp, g_global_pool);
    apr_pool_tag(ptemp, "ptemp");

    snprintf(sql_statement, SQL_STATEMENT_LEN, "select * from server_dir_webtamper where server='%s';", wsname);
    res = NULL;
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "init webserver cfg failure");
        goto __exit;    
    }   
    
    nrows = apr_dbd_num_tuples(ap_logdb_driver, res);
    if (nrows == 1) {
        snprintf(sql_statement, SQL_STATEMENT_LEN, "update server_dir_webtamper set totalsize=%llu where server='%s';",
            wb->cfg.disksize, wb->cfg.wsname);  
    } else {
        snprintf(sql_statement, SQL_STATEMENT_LEN, "insert into server_dir_webtamper values('%s', '%s', %llu);",
            wsname, backuproot, wb->cfg.disksize);
    } 

    rv = log_send(sql_statement, 0);
    if (rv < 0) {
        TAMPER_LOG_WRITE(PE_LOG_WARN, "send disk usage info to log server failed.");
    }    

__exit:
    apr_pool_destroy(ptemp);
    return 0;
}

static void admin_log_io_term(apr_pool_t *ptemp, admin_log_t *adminlog, char *action)
{
    struct utmp *u;
    char tname[32];
  
    strncpy(tname, ttyname(0), 32);
    adminlog->time = apr_time_now() / APR_USEC_PER_SEC;
    while ((u = getutent()) != NULL) {
        if(u->ut_type == USER_PROCESS) {
            if (!strcmp(u->ut_line, tname + 5)) { /* 去除掉前面的/dev/，因为u->ut_line中除去掉/dev/ */
                adminlog->admin_name = apr_pstrdup(ptemp, u->ut_user);
                
                if (!strcmp(u->ut_host, "")) {
                    adminlog->ip = apr_pstrdup(ptemp, "localhost");
                } else {
                    adminlog->ip = apr_pstrdup(ptemp, u->ut_host);
                }
                
                adminlog->tty = apr_pstrdup(ptemp, tname);
                break;
            }
        }
    }

    endutent();
    setutent();    
    adminlog->action = apr_pstrdup(ptemp, action);
}

static void admin_log_io_socket_unix(cparser_context_t *context, admin_log_t *adminlog, char *action)
{
    char *usrname, *ip, *tty;

    /* 时间 */
    adminlog->time = apr_time_now() / APR_USEC_PER_SEC;
    /* 用户名 */
    usrname = cparser_get_client_username(context->parser);
    adminlog->admin_name = usrname ? usrname : "";
    /* IP */
    ip = cparser_get_client_ip(context->parser);
    adminlog->ip = ip ? ip : "";
    /* 终端名 */
    tty = cparser_get_client_terminal(context->parser);
    adminlog->tty = tty ? tty : "";
    /* 动作 */
    adminlog->action = action;   
}

void admin_log_process(cparser_context_t *context, char *action)
{
    admin_log_t adminlog;
    apr_pool_t *ptemp;
    char buf[1024];
    int rv;

    if (!context || !action) {
        return ;
    }

    memset(&adminlog, 0, sizeof(admin_log_t));    
    switch (context->parser->cfg.io_type) {
    case IO_SOCKET_UNIX: 
        if (!cparser_client_connecting(context->parser)) {
            /* 无客户端连接的时候不记录管理日志 */
            return;
        } 
        admin_log_io_socket_unix(context, &adminlog, action);
        snprintf(buf, 1024, "insert into admin_log_table values(%llu, '%s', '%s', '%s', '%s', '%s')", 
            (unsigned long long)adminlog.time, adminlog.ip, adminlog.admin_name, 
            adminlog.tty, adminlog.action, "anti-tamper");
        break;
     case IO_TERM:
        apr_pool_create(&ptemp, g_global_pool);
        admin_log_io_term(ptemp, &adminlog, action);
        snprintf(buf, 1024, "insert into admin_log_table values(%llu, '%s', '%s', '%s', '%s', '%s')", 
            (unsigned long long)adminlog.time, adminlog.ip, adminlog.admin_name, 
            adminlog.tty, adminlog.action, "anti-tamper");
        apr_pool_destroy(ptemp);
        break;
     default:
        return;      
    }
 
    /* 发送到日志服务器 */
    rv = log_send(buf, 0);
    if (rv < 0) {
        TAMPER_LOG_WRITE(PE_LOG_WARN, "send admin log to log server failed.");
    }
    
    return;
}

cparser_result_t cparser_cmd_enable(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT], buf[COMMAND_LEN_MAX];
    
    assert(context);
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, NULL); 
        context->parser->root_level--;
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "enable");
    admin_log_process(context, buf);
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s#", g_cli_prompt);
    
    return cparser_submode_enter(context->parser, NULL, prompt);
}

cparser_result_t cparser_cmd_st_write(cparser_context_t *context)
{
    FILE *fp;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    fp = fopen(context->parser->default_conf_file, "w");
    if (!fp) {
        cparser_printf(context, "Fail to open %s.\n", context->parser->default_conf_file);
        return CPARSER_NOT_OK;
    }
    context->parser->fp = fp;

    cparser_write_cmd(context->parser);
    fclose(fp);

    snprintf(buf, COMMAND_LEN_MAX, "write");
    admin_log_process(context, buf);
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_st_load(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "load");
    admin_log_process(context, buf);
    return cparser_load_cmd(context->parser, context->parser->default_conf_file);
}

cparser_result_t cparser_cmd_st_configure(cparser_context_t *context)
{
    char prompt[CPARSER_MAX_PROMPT];
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        cparser_walk(context->parser, cparser_running_conf_walker, NULL, NULL); 
        context->parser->root_level--;
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "configure");
    admin_log_process(context, buf);
    snprintf(prompt, CPARSER_MAX_PROMPT, "%s(config)#", g_cli_prompt);
    
    return cparser_submode_enter(context->parser, NULL, prompt);
}

cparser_result_t cparser_cmd_monther_no_tamper_name(cparser_context_t *context,
    char **name_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX] = {0};
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    apr_pool_t *ptemp;
    apr_dbd_results_t *res;
    struct timespec timespec;
    struct timeval now;    
    int rv;

    if (context == NULL || name_ptr == NULL || *name_ptr == NULL) {
        return CPARSER_NOT_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    wb = (webserver_t *)find_webserver(&webserver_listhead, *name_ptr);
    if (wb) {
        wb->cfg.destroywb = 1;
        
        apr_pool_create(&ptemp, g_global_pool);
        apr_pool_tag(ptemp, "ptemp");
        
        snprintf(sql_statement, SQL_STATEMENT_LEN, "delete from server_dir_webtamper where server='%s';", wb->cfg.wsname);
        res = NULL;        
        rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
        if (rv != APR_SUCCESS) {
            TAMPER_LOG_WRITE(PE_LOG_FATAL, "delete  tamper %s failure\n", *name_ptr);
            goto __exit;    
        }

        snprintf(buf, COMMAND_LEN_MAX, "no tamper %s", *name_ptr);
        admin_log_process(context, buf);
    
__exit: 
        pthread_mutex_lock(&list_mutex);
        left_disksize += wb->cfg.disksize;
        pthread_mutex_unlock(&list_mutex); 
    
        if (!wb->running) {
            uninit_webserver_cfg(wb);
        } else {
            wb->cfg.destroywb = 1;
            
            /* 等待信号量 */
            gettimeofday(&now, NULL);
            timespec.tv_sec = now.tv_sec + 120;
            timespec.tv_nsec = now.tv_usec * 1000; 
            while (sem_timedwait(&wb->destroy_wait, &timespec) == -1 && errno == EINTR) {
                continue;
            }
        }       
        
        apr_pool_destroy(ptemp);
    } else {
        cparser_printf(context, "the web server %s do not exist.\n", *name_ptr);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_monther_tamper_name(cparser_context_t *context,
    char **name_ptr)
{
    webserver_t *wb;
    int ret;
    char prompt[CPARSER_MAX_PROMPT], buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    /* 处理C2P状态 */
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        context->parser->root_level++;
        context->parser->root[context->parser->root_level] = context->parser->cur_node->children;
        list_for_each_entry(wb, &webserver_listhead, list, webserver_t) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return CPARSER_NOT_OK;
                }
                
                fprintf(context->parser->fp, "tamper %s\n", wb->cfg.wsname);
            } else {
                cparser_printf(context, "!\n");
                cparser_printf(context, "tamper %s\n", wb->cfg.wsname);
            }

            cparser_walk(context->parser, cparser_running_conf_walker, NULL, wb->cfg.wsname);
        }
        context->parser->root_level--;
    } else {
        if (name_ptr == NULL || *name_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        if (strlen(*name_ptr) + 1 <= MAX_WSNAME_LEN) {
            strcpy(g_last_wsname, *name_ptr);
        } else {
            cparser_printf(context, "tamper characters number exceed %d\n", MAX_WSNAME_LEN);
            return CPARSER_NOT_OK;
        }
        snprintf(prompt, CPARSER_MAX_PROMPT, "%s(tamper)#", g_cli_prompt);

        wb = (webserver_t *)find_webserver(&webserver_listhead, g_last_wsname);
        if (wb) {
            snprintf(buf, COMMAND_LEN_MAX, "tamper %s", *name_ptr);
            admin_log_process(context, buf);
            return cparser_submode_enter(context->parser, g_last_wsname, prompt);
        } else {
            pthread_mutex_lock(&list_mutex);
            if (left_disksize < UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE)) {
                pthread_mutex_unlock(&list_mutex);
                cparser_printf(context, "the disk size is not enough.\n");
                return CPARSER_NOT_OK;
            }     
            pthread_mutex_unlock(&list_mutex);
        }

        /* 若不存在则创建一个 */
        wb = (webserver_t *)malloc(sizeof(webserver_t));
        if (wb == NULL) {
            return CPARSER_OK;
        }
        memset(wb, 0, sizeof(webserver_t));
        wb->suffix_changed = 1;

        ret = init_webserver_cfg(wb, g_last_wsname);
        if (ret == -1) {
            free(wb);
            return CPARSER_OK;
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "tamper %s", *name_ptr);
        admin_log_process(context, buf);
        
        pthread_mutex_lock(&list_mutex);
        list_add_tail(&wb->list, &webserver_listhead);
        pthread_mutex_unlock(&list_mutex);

        return cparser_submode_enter(context->parser, g_last_wsname, prompt);
    }

    return CPARSER_OK;
}

static webserver_t *cparser_get_webserver(cparser_context_t *context)
{
    webserver_t *wb;
    char *pwsname;
    
    pwsname = (char *)context->cookie[context->parser->root_level];
    if (pwsname == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&list_mutex);
    wb = (webserver_t *)find_webserver(&webserver_listhead, pwsname);
    pthread_mutex_unlock(&list_mutex);

    return wb;
}

cparser_result_t cparser_cmd_son_description_content(cparser_context_t *context,
    char **content_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n", (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.description[0] != '\0') {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " description %s\n", wb->cfg.description);
            } else {
                cparser_printf(context, " description %s\n", wb->cfg.description);
            }
        }

        return CPARSER_OK;
    } else {
        if (content_ptr == NULL || *content_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        if (strlen(*content_ptr) + 1 <= MAX_DESCRIPTION_LEN) {
            strncpy(wb->cfg.description, *content_ptr, MAX_DESCRIPTION_LEN);
            snprintf(buf, COMMAND_LEN_MAX, "description %s", *content_ptr);
            admin_log_process(context, buf);
        } else {
            cparser_printf(context, "description characters number exceed %d\n", MAX_DESCRIPTION_LEN);
            return CPARSER_NOT_OK;
        }
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_description(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX] = {0};

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.description[0] = '\0';
        snprintf(buf, COMMAND_LEN_MAX, "no description");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_email(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }    

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.email[0] = '\0';
        snprintf(buf, COMMAND_LEN_MAX, "no email");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_document_root(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.server_root[0] = '\0';
        snprintf(buf, COMMAND_LEN_MAX, "no document-root");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}
cparser_result_t cparser_cmd_son_no_monitor_folder_depth(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.depth = DEFAULT_DEPTH;
        wb->cfg.server_root[0] = '\0';
        snprintf(buf, COMMAND_LEN_MAX, "no monitor-folder depth");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_monitor_folder_root_folder(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.root_interval = DEFAULT_ROOT_INTERVAL;
        snprintf(buf, COMMAND_LEN_MAX, "no monitor-folder root-folder");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_monitor_folder_other_folder(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.other_interval = DEFAULT_OTHER_INTERVAL;
        snprintf(buf, COMMAND_LEN_MAX, "no monitor-folder other-folder");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_monitor_file_size(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.maxfilesize = UNIT_CONVERT_KB_TO_B(DEFAULT_MAXFILESIZE);
        snprintf(buf, COMMAND_LEN_MAX, "no monitor-file-size");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_monitor_file_type_exclude_extension(cparser_context_t *context,
    char **extension_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (extension_ptr == NULL || *extension_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        suffix_t *old_suffix;
        suffix_t *tmp_suffix;
        int found;

        found = 0;
        list_for_each_entry_safe(old_suffix, tmp_suffix, &(wb->cfg.suffix_head), list, suffix_t) {
            if (!strcmp(old_suffix->suffix, *extension_ptr)) {
                list_del_init(&(old_suffix->list));
                free(old_suffix);
                found++;
            }
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "no monitor-file-type exclude %s", *extension_ptr);
        admin_log_process(context, buf);

        if (!found) {
            return CPARSER_NOT_OK;
        }

        wb->suffix_changed = 1;
        
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_son_no_connect(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.host[0] = '\0';
        wb->cfg.prtcl_port = 0;
        wb->cfg.prtcl_name[0] = '\0';
        wb->cfg.username[0] = '\0';
        wb->cfg.password[0] = '\0';

        snprintf(buf, COMMAND_LEN_MAX, "no connect");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_restore_mode(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.isautorestore = DEFAULT_AUTORESTORE;

        snprintf(buf, COMMAND_LEN_MAX, "no restore-mode");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_monitor(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.enable = 0;
        snprintf(buf, COMMAND_LEN_MAX, "no monitor");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_no_disk_size(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX] = {0};
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    int rv;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE) <= (left_disksize + wb->cfg.disksize)) {
            pthread_mutex_lock(&list_mutex);
            /* 由兆转化为字节 */
            left_disksize += wb->cfg.disksize;
            left_disksize -= UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE);
            wb->cfg.disksize = UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE);
            pthread_mutex_unlock(&list_mutex);   
        } else {
            cparser_printf(context, "Set the total disksize to default size failed!\n");
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "no disk-size");
        admin_log_process(context, buf);

        /* 发送磁盘信息到日志服务器 */    
        snprintf(sql_statement, SQL_STATEMENT_LEN, "update server_dir_webtamper set totalsize=%llu where server='%s';",
            wb->cfg.disksize, wb->cfg.wsname);
        rv = log_send(sql_statement, 0);
        if (rv < 0) {
            TAMPER_LOG_WRITE(PE_LOG_INFO, "send disk usage info to log server failed.");
        }               
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_email_address(cparser_context_t *context,
    char **address_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.email[0] != '\0') {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " email %s\n", wb->cfg.email);
            } else {
                cparser_printf(context, " email %s\n", wb->cfg.email);
            }
        }
    } else {
        if (address_ptr == NULL || *address_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        if (strlen(*address_ptr) + 1 <= MAX_EMAIL_LEN) {
            strncpy(wb->cfg.email, *address_ptr, MAX_EMAIL_LEN);

            snprintf(buf, COMMAND_LEN_MAX, "email %s", *address_ptr);
            admin_log_process(context, buf);
        } else {
            cparser_printf(context, "email characters number exceed %d\n", MAX_EMAIL_LEN);
            return CPARSER_NOT_OK;
        }
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_document_root_path(cparser_context_t *context,
    char **path_ptr)
{
    webserver_t *wb;
    char *path;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.server_root[0] != '\0') {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " document-root %s\n", wb->cfg.server_root);
            } else {
                cparser_printf(context, " document-root %s\n", wb->cfg.server_root);
            }
        }
    } else {
        if (path_ptr == NULL || *path_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        wb->cfg.server_root[0] = '\0';
        if (strlen(*path_ptr) + 1 <= MAX_SERVERROOT_LEN) {
            path = *path_ptr;
            if (*(path + strlen(path) - 1) == '/') {
                strcpy(wb->cfg.server_root, path);
            } else {
                sprintf(wb->cfg.server_root, "%s/", path);
            }

            snprintf(buf, COMMAND_LEN_MAX, "document-root %s", *path_ptr);
            admin_log_process(context, buf);
        } else {
            cparser_printf(context, "document-root characters number exceed %d\n", MAX_SERVERROOT_LEN);
            return CPARSER_NOT_OK;
        }
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_monitor_folder_depth_level(cparser_context_t *context,
    int32_t *level_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.depth != DEFAULT_DEPTH) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " monitor-folder depth %d\n", wb->cfg.depth);
            } else {
                cparser_printf(context, " monitor-folder depth %d\n", wb->cfg.depth);
            }
        }
    } else {
        if (level_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        wb->cfg.depth = *level_ptr;

        snprintf(buf, COMMAND_LEN_MAX, "monitor-folder depth %d", *level_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_monitor_folder_root_folder_seconds(cparser_context_t *context,
    int32_t *seconds_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.root_interval != DEFAULT_ROOT_INTERVAL) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " monitor-folder root-folder %d\n", wb->cfg.root_interval);
            } else {
                cparser_printf(context, " monitor-folder root-folder %d\n", wb->cfg.root_interval);
            }
        }
    } else {
        if (seconds_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        if (*seconds_ptr > wb->cfg.other_interval) {
            cparser_printf(context, "the root path check interval should be shorter than other path check interval.\n");
            return CPARSER_NOT_OK;    
        }
        
        wb->cfg.root_interval = *seconds_ptr;

        snprintf(buf, COMMAND_LEN_MAX, "monitor-folder root-folder %d", *seconds_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_monitor_folder_other_folder_seconds(cparser_context_t *context,
    int32_t *seconds_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.other_interval != DEFAULT_OTHER_INTERVAL) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " monitor-folder other-folder %d\n", wb->cfg.other_interval);
            } else {
                cparser_printf(context, " monitor-folder other-folder %d\n", wb->cfg.other_interval);
            }
        }

    } else {
        if (seconds_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        if (*seconds_ptr < wb->cfg.root_interval) {
            cparser_printf(context, "the root path check interval should be longer than other path check interval.\n");
            return CPARSER_NOT_OK;    
        }        
        
        wb->cfg.other_interval = *seconds_ptr;

        snprintf(buf, COMMAND_LEN_MAX, "monitor-folder other-folder %d", *seconds_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_monitor_file_size_number(cparser_context_t *context,
    uint32_t *number_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.maxfilesize != UNIT_CONVERT_KB_TO_B(DEFAULT_MAXFILESIZE)) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                assert(context->parser->fp);
                fprintf(context->parser->fp, " monitor-file-size %llu\n", UNIT_CONVERT_B_TO_KB(wb->cfg.maxfilesize));
            } else {
                cparser_printf(context, " monitor-file-size %llu (KiB)\n", UNIT_CONVERT_B_TO_KB(wb->cfg.maxfilesize));
            }
        }

    } else {
        if (number_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        wb->cfg.maxfilesize = UNIT_CONVERT_KB_TO_B(*number_ptr);

        snprintf(buf, COMMAND_LEN_MAX, "monitor-file-size %d", *number_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_monitor_file_type_exclude_extension(cparser_context_t *context,
    char **extension_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];
            
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        suffix_t *old_suffix;

        list_for_each_entry(old_suffix, &wb->cfg.suffix_head, list, suffix_t) {
            if (context->parser->mode == CPARSER_MODE_WRITE) { 
                assert(context->parser->fp);
                fprintf(context->parser->fp, " monitor-file-type exclude %s\n", old_suffix->suffix);
            } else {
                cparser_printf(context, " monitor-file-type exclude %s\n", old_suffix->suffix);
            }
        }
        
        return CPARSER_OK;
    } else {
        if (extension_ptr == NULL || *extension_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        suffix_t *new_suffix = (suffix_t *)malloc(sizeof(suffix_t));
        if (new_suffix == NULL) {
            return CPARSER_NOT_OK;
        }

        strncpy(new_suffix->suffix, *extension_ptr, MAX_SUFFIX_LEN);

        list_add_tail(&(new_suffix->list), &(wb->cfg.suffix_head));

        wb->suffix_changed = 1;
        
        snprintf(buf, COMMAND_LEN_MAX, "monitor-file-type exclude %s", *extension_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_son_connect_protocol_protocol_object_var_port_number_username_name_password_cipher_text_pw(cparser_context_t *context,
    char **protocol_ptr,
    char **object_ptr,
    char **var_ptr,
    uint32_t *number_ptr,
    char **name_ptr,
    char **pw_ptr)
{
    webserver_t *wb;
    struct in_addr addr;
    char buf[COMMAND_LEN_MAX];
    apr_pool_t *ptemp;
    unsigned char *encrypt_password;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        apr_pool_create(&ptemp, g_global_pool);
        apr_pool_tag(ptemp, "ptemp");

        encrypt_password = tripleDes(ptemp, (const unsigned char *)(wb->cfg.password), 
                               get_3des_key(ptemp, PASSWORD_KEY), 
                               get_3des_vector(ptemp, PASSWORD_KEY),
                               DES_ENCRYPT);
        if (encrypt_password == NULL) {
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }
        
        if (wb->cfg.host[0] != '\0') {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    apr_pool_destroy(ptemp);
                    return CPARSER_NOT_OK;
                }
                
                fprintf(context->parser->fp, " connect protocol %s server-ip %s port %d username %s "
                        "password cipher-text %s\n", wb->cfg.prtcl_name, wb->cfg.host, wb->cfg.prtcl_port,
                        wb->cfg.username, encrypt_password);
            } else {
                cparser_printf(context, " connect protocol %s server-ip %s port %d username %s password cipher-text %s\n",
                        wb->cfg.prtcl_name, wb->cfg.host, wb->cfg.prtcl_port, wb->cfg.username, encrypt_password);
            }
        }
        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    } else {
        if (protocol_ptr == NULL || *protocol_ptr == NULL
                || object_ptr == NULL || *object_ptr == NULL
                || var_ptr == NULL || *var_ptr == NULL
                || number_ptr == NULL
                || name_ptr == NULL || *name_ptr == NULL
                || pw_ptr == NULL || *pw_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        apr_pool_create(&ptemp, g_global_pool);
        apr_pool_tag(ptemp, "ptemp");
        
        /* protocol */
        if (strlen(*protocol_ptr) + 1 <= MAX_PRTCLNAME_LEN ) {
            if (!strcmp(*protocol_ptr, "sftp")) {
                strcpy(wb->cfg.prtcl_name, *protocol_ptr);
            }
        } else {
            cparser_printf(context, "protocol characters number exceed %d\n", MAX_HOST_LEN);
            apr_pool_destroy(ptemp);
            return CPARSER_NOT_OK;
        }

        /* server ip */
        if (!strcmp(*object_ptr, "server-ip")) {
            if (inet_pton(AF_INET, *var_ptr, &addr) <= 0) {
                cparser_printf(context, "the server ip you enter incorrect\n");
                /* 单个参数出问题不需要返回 */
            } else {
                strcpy(wb->cfg.host, *var_ptr);
            }
        }

        /* port */
        wb->cfg.prtcl_port = (int)*number_ptr;

        /* username */
        if (strlen(*name_ptr) + 1 < MAX_USERNAME_LEN) {
            strcpy(wb->cfg.username, *name_ptr);
        } else {
            cparser_printf(context, "username characters number exceed %d\n", MAX_USERNAME_LEN);
        }

        /* password */
        if (strlen(*pw_ptr) + 1 <= MAX_PASSWORD_LEN) {
            encrypt_password = tripleDes(ptemp, (const unsigned char *)(*pw_ptr), 
                                get_3des_key(ptemp, PASSWORD_KEY), 
                                get_3des_vector(ptemp, PASSWORD_KEY),
                                DES_DECRYPT);
            
            if (encrypt_password) {
                strcpy(wb->cfg.password, (const char *)encrypt_password);
            }
        } else {
            cparser_printf(context, "password characters number exceed %d\n", MAX_PASSWORD_LEN);
        }

        snprintf(buf, COMMAND_LEN_MAX, "connect protocol %s %s %s port %d username %s password cipher-text %s", 
            *protocol_ptr, *object_ptr, *var_ptr, *number_ptr, *name_ptr, *pw_ptr);
        admin_log_process(context, buf);

        apr_pool_destroy(ptemp);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_son_connect_protocol_protocol_object_var_port_number_username_name_password_pw(cparser_context_t *context,
    char **protocol_ptr,
    char **object_ptr,
    char **var_ptr,
    uint32_t *number_ptr,
    char **name_ptr,
    char **pw_ptr)
{
    webserver_t *wb;
    struct in_addr addr;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        assert(protocol_ptr && *protocol_ptr && object_ptr && *object_ptr && *var_ptr && var_ptr
                && number_ptr && name_ptr && *name_ptr && pw_ptr && *pw_ptr);
        /* protocol */
        if (strlen(*protocol_ptr) + 1 <= MAX_PRTCLNAME_LEN ) {
            if (!strcmp(*protocol_ptr, "sftp")) {
                strcpy(wb->cfg.prtcl_name, *protocol_ptr);
            }
        } else {
            cparser_printf(context, "protocol characters number exceed %d\n", MAX_HOST_LEN);
            return CPARSER_NOT_OK;
        }

        /* server ip */
        if (!strcmp(*object_ptr, "server-ip")) {
            if (inet_pton(AF_INET, *var_ptr, &addr) <= 0) {
                cparser_printf(context, "the server ip you enter incorrect\n");
                /* 单个参数出问题不需要返回 */
            } else {
                strcpy(wb->cfg.host, *var_ptr);
            }
        }

        /* port */
        wb->cfg.prtcl_port = (int)*number_ptr;

        /* username */
        if (strlen(*name_ptr) + 1 < MAX_USERNAME_LEN) {
            strcpy(wb->cfg.username, *name_ptr);
        } else {
            cparser_printf(context, "username characters number exceed %d\n", MAX_USERNAME_LEN);
        }

        /* password */
        if (strlen(*pw_ptr) + 1 <= MAX_PASSWORD_LEN) {
            strcpy(wb->cfg.password, *pw_ptr);
        } else {
            cparser_printf(context, "password characters number exceed %d\n", MAX_PASSWORD_LEN);
        }

        snprintf(buf, COMMAND_LEN_MAX, "connect protocol %s %s %s port %d username %s password cipher-text %s", 
            *protocol_ptr, *object_ptr, *var_ptr, *number_ptr, *name_ptr, *pw_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_restore_mode_option(cparser_context_t *context,
    char **option_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            if (context->parser->fp == NULL) {
                return CPARSER_NOT_OK;
            }
            
            fprintf(context->parser->fp, " restore-mode %s\n", restore_type[wb->cfg.isautorestore]);
        } else {
            cparser_printf(context, " restore-mode %s\n", restore_type[wb->cfg.isautorestore]);
        }
    } else {
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        wb->cfg.isautorestore = (!strcmp(*option_ptr, "manual")) ? 0 : 1;
        if (wb->cfg.isautorestore) {
            pthread_mutex_lock(&wb->wbmutex);
            svn_copy_record(wb->man_restore, wb->svn);
            pthread_mutex_unlock(&wb->wbmutex);
        } else {
            pthread_mutex_lock(&wb->wbmutex);
            svn_copy_record(wb->svn, wb->man_restore);
            pthread_mutex_unlock(&wb->wbmutex);
        }
        
        snprintf(buf, COMMAND_LEN_MAX, "restore-mode %s", *option_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_monitor_option(cparser_context_t *context,
    char **option_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (context->parser->mode == CPARSER_MODE_WRITE) {
            assert(context->parser->fp);
            fprintf(context->parser->fp, " monitor %s\n", monitor_type[wb->cfg.enable]);
        } else {
            cparser_printf(context, " monitor %s\n", monitor_type[wb->cfg.enable]);
        }
    } else {
        if (option_ptr == NULL || *option_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        if (wb->running) {
            wb->cfg.enable = (!strcmp(*option_ptr, "disable")) ? 0 : 1;
            if (wb->cfg.enable) {
                sem_post(&wb->monitor_wait);
            }
        }

        snprintf(buf, COMMAND_LEN_MAX, "monitor %s", *option_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

/* disk-size <INT:size> */
cparser_result_t cparser_cmd_son_disk_size_size(cparser_context_t *context,
    int32_t *size_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX] = {0};
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    int rv;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s is not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        if (wb->cfg.disksize != UNIT_CONVERT_MB_TO_B(DEFAULT_DISKSIZE)) {
            if (context->parser->mode == CPARSER_MODE_WRITE) {
                if (context->parser->fp == NULL) {
                    return CPARSER_NOT_OK;
                }
                fprintf(context->parser->fp, " disk-size %llu\n", UNIT_CONVERT_B_TO_MB(wb->cfg.disksize));
            } else {
                cparser_printf(context, " disk-size %llu (MiB)\n", UNIT_CONVERT_B_TO_MB(wb->cfg.disksize));
            }
        }
    } else {
        if (size_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        snprintf(buf, COMMAND_LEN_MAX, "disk-size %d", *size_ptr);
        admin_log_process(context, buf);
                
        if (UNIT_CONVERT_MB_TO_B(*size_ptr) <= (left_disksize + wb->cfg.disksize)) {
            pthread_mutex_lock(&list_mutex);
            /* 由兆转化为字节 */
            left_disksize += wb->cfg.disksize;
            left_disksize -= UNIT_CONVERT_MB_TO_B(*size_ptr);
            wb->cfg.disksize = UNIT_CONVERT_MB_TO_B(*size_ptr);
            pthread_mutex_unlock(&list_mutex);    
        } else {
            cparser_printf(context, "Exceed the left disksize!\n");
            return CPARSER_NOT_OK;
        }
        
        /* zwp:发送磁盘信息到日志服务器 */  
        snprintf(sql_statement, SQL_STATEMENT_LEN, "update server_dir_webtamper set totalsize=%llu where server='%s';",
            wb->cfg.disksize, wb->cfg.wsname);
        rv = log_send(sql_statement, 0);
        if (rv < 0) {
            TAMPER_LOG_WRITE(PE_LOG_INFO, "Send disk usage info to log server failed.");
        }   
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_restore_tamper_all(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_NOT_OK;
    } else {
        pthread_mutex_lock(&wb->wbmutex);
        svn_copy_record(wb->svn, wb->man_restore);
        pthread_mutex_unlock(&wb->wbmutex);
        
        snprintf(buf, COMMAND_LEN_MAX, "restore-tamper all");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_restore_tamper_file_name(cparser_context_t *context,
    char **name_ptr)
{
    webserver_t *wb;
    svn_node_t *node;
    char buf[COMMAND_LEN_MAX];
    char filename[MAX_PATH_LEN] = {0};

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (name_ptr == NULL || *name_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
        
        sprintf(filename, "%s%s", wb->local_root, *name_ptr + strlen(wb->cfg.server_root));
        node = svn_get_node(wb->svn, filename);
        if (node) {
            pthread_mutex_lock(&wb->wbmutex);
            svn_del_node(wb->svn, node);
            svn_add_node(wb->man_restore, node);
            pthread_mutex_unlock(&wb->wbmutex);
        }

        snprintf(buf, COMMAND_LEN_MAX, "restore-tamper file %s", *name_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

static void printf_view_cmd_result(cparser_context_t *context, char *cmd)
{
    FILE* fp;
    char content[MAX_BUF_LEN];
    int rv;

    fp = popen(cmd, "r");
    if (fp == NULL) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "%s popen fail!", cmd);
        return;
    }

    while (1) {
        memset(content, 0, MAX_BUF_LEN);
        rv = fread(content, 1, MAX_BUF_LEN, fp);
        if (rv > 0) {
            cparser_printf(context, "%s", content);
        } else {
            break;
        }
    }
    
    pclose(fp);    
    return;
}

cparser_result_t cparser_cmd_son_view_file_content_name(cparser_context_t *context,
    char **name_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];
    char cmd[MAX_PATH_LEN] = {0};
    int server_path_len;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (name_ptr == NULL || *name_ptr == NULL) {
            return CPARSER_NOT_OK;
        }  
        
        server_path_len = strlen(wb->cfg.server_root);
        if (strncmp(*name_ptr, wb->cfg.server_root, server_path_len) != 0) {
            cparser_printf(context, "file path is error!\n");
            return CPARSER_NOT_OK;
        }
        
        snprintf(cmd, MAX_PATH_LEN, "cat %s%s", wb->local_root, *name_ptr + server_path_len);  
        printf_view_cmd_result(context, cmd);
        snprintf(buf, COMMAND_LEN_MAX, "view file-content %s", *name_ptr);
        admin_log_process(context, buf);
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_son_view_tamper_content_name(cparser_context_t *context,
    char **name_ptr)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];
    char file1[MAX_PATH_LEN] = {0};
    char file2[MAX_PATH_LEN] = {0};
    char cmd[MAX_PATH_LEN] = {0};
    int server_path_len;
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (name_ptr == NULL || *name_ptr == NULL) {
            return CPARSER_NOT_OK;
        }

        server_path_len = strlen(wb->cfg.server_root);
        if (strncmp(*name_ptr, wb->cfg.server_root, server_path_len) != 0) {
            cparser_printf(context, "file path is error!\n");
            return CPARSER_NOT_OK;
        }
        
        snprintf(file1, MAX_PATH_LEN, "%s%s", wb->local_root, *name_ptr + server_path_len);
        snprintf(file2, MAX_PATH_LEN, "%s%s", wb->change_root, *name_ptr + server_path_len);

        if (file1[0] != '\0' || file2[0] != '\0') {
            sprintf(cmd, "diff %s %s", file1, file2);
            printf_view_cmd_result(context, cmd);
        }

        snprintf(buf, COMMAND_LEN_MAX, "view tamper-content %s", *name_ptr);
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_view_tamper_filename(cparser_context_t *context)
{
    webserver_t *wb;
    char *pwsname;
    struct list_head *pos;
    svn_node_t *node;
    char buf[COMMAND_LEN_MAX];
    char filename[MAX_PATH_LEN] = {0};
    apr_pool_t *ptemp;
    int num = 0;   
    char *type_format;
    char *type;
    /* 修改 删除 增加 */
    const char *tamper_type_utf8[] = {
        "\xE4\xBF\xAE\xE6\x94\xB9",
        "\xE5\x88\xA0\xE9\x99\xA4", 
        "\xE5\xA2\x9E\xE5\x8A\xA0", 
        NULL
    };
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  

    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        apr_pool_create(&ptemp, g_global_pool);
        apr_pool_tag(ptemp, "ptemp");
        snprintf(buf, COMMAND_LEN_MAX, "view tamper-filename");
        pwsname = wb->cfg.wsname;
        cparser_printf(context, "-------------------------------------------------------\n");
        cparser_printf(context, "No.    Tamper-Name         Tamper-Type    Tamper-File\n"); 
        
        if (!wb->running) {
            admin_log_process(context, buf);
            apr_pool_destroy(ptemp);  
            return CPARSER_OK;
        }
        
        pthread_mutex_lock(&wb->wbmutex);
        type_format = apr_psprintf(ptemp, "%%-%ds", 11 + (strlen(tamper_type_utf8[2]) / 3) );
        type = apr_psprintf(ptemp, type_format, tamper_type_utf8[2]);
        list_for_each(pos, &wb->svn->add_files.brother) {
            node = list_entry(pos, svn_node_t, brother);
            sprintf(filename, "%s%s", wb->cfg.server_root, node->filename + strlen(wb->local_root));
            cparser_printf(context, "%-3d    %-16s    %-s    %s\n", ++num, pwsname, type, filename);
        }
        
        type_format = apr_psprintf(ptemp, "%%-%ds", 11 + (strlen(tamper_type_utf8[1]) / 3) );
        type = apr_psprintf(ptemp, type_format, tamper_type_utf8[1]);
        list_for_each(pos, &wb->svn->delete_files.brother) {
            node = list_entry(pos, svn_node_t, brother);
            sprintf(filename, "%s%s", wb->cfg.server_root, node->filename + strlen(wb->local_root));
            cparser_printf(context, "%-3d    %-16s    %-s    %s\n", ++num, pwsname, type, filename);
        }
        
        type_format = apr_psprintf(ptemp, "%%-%ds", 11 + (strlen(tamper_type_utf8[0]) / 3) );
        type = apr_psprintf(ptemp, type_format, tamper_type_utf8[0]); 
        list_for_each(pos, &wb->svn->update_files.brother) {
            node = list_entry(pos, svn_node_t, brother);
            sprintf(filename, "%s%s", wb->cfg.server_root, node->filename + strlen(wb->local_root));
            cparser_printf(context, "%-3d    %-16s    %-s    %s\n", ++num, pwsname, type, filename);
        }

        pthread_mutex_unlock(&wb->wbmutex);
        admin_log_process(context, buf);
        apr_pool_destroy(ptemp);    
        return CPARSER_OK;
    }
}

cparser_result_t cparser_cmd_son_clear_tamper_all(cparser_context_t *context)
{
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        wb->cfg.iscomit = 1;

        pthread_mutex_lock(&wb->wbmutex);
        svn_copy_record(wb->svn, wb->man_reserve);
        pthread_mutex_unlock(&wb->wbmutex);
        
        snprintf(buf, COMMAND_LEN_MAX, "clear-tamper all");
        admin_log_process(context, buf);
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_son_clear_tamper_file_name(cparser_context_t *context,
    char **name_ptr)
{
    webserver_t *wb;
    svn_node_t *node;
    char buf[COMMAND_LEN_MAX];
    char filename[MAX_PATH_LEN] = {0};
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }  
    
    wb = cparser_get_webserver(context);
    if (wb == NULL) {
        cparser_printf(context, "the web server：%s not existing\n",
                (char *)context->cookie[context->parser->root_level]);
        return CPARSER_OK;
    }

    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        if (name_ptr == NULL || *name_ptr == NULL) {
            return CPARSER_NOT_OK;
        }
    
        sprintf(filename, "%s%s", wb->local_root, *name_ptr + strlen(wb->cfg.server_root));
        node = svn_get_node(wb->svn, filename);
        if (node) {
            pthread_mutex_lock(&wb->wbmutex);
            svn_del_node(wb->svn, node);
            svn_add_node(wb->man_reserve, node);
            pthread_mutex_unlock(&wb->wbmutex);
            wb->cfg.iscomit = 1;
        }
    }
    
    snprintf(buf, COMMAND_LEN_MAX, "clear-tamper file %s", *name_ptr);
    admin_log_process(context, buf);
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_load(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    return cparser_load_cmd(context->parser, context->parser->default_conf_file);
}

/* show tree */
static char *format_time(apr_pool_t *ptemp, int year_int,int month_int, int day_int, int hour_int, 
                int minute_int, int second_int)
{
    char *month_str;
    char *day_str;
    char *hour_str;
    char *minute_str;
    char *second_str;

    if (month_int < 10) {
        month_str = apr_psprintf(ptemp, "%d%d", 0, month_int);
    } else {
        month_str = apr_psprintf(ptemp, "%d", month_int);
    }

    if (day_int < 10) {
        day_str = apr_psprintf(ptemp, "%d%d", 0, day_int);
    } else {
        day_str = apr_psprintf(ptemp, "%d", day_int);
    }

    if (hour_int < 10) {
        hour_str = apr_psprintf(ptemp, "%d%d", 0, hour_int);
    } else {
        hour_str = apr_psprintf(ptemp, "%d", hour_int);
    }

    if (minute_int < 10) {
        minute_str = apr_psprintf(ptemp, "%d%d", 0, minute_int);
    } else {
        minute_str = apr_psprintf(ptemp, "%d", minute_int);
    }

    if (second_int < 10) {
        second_str = apr_psprintf(ptemp, "%d%d", 0, second_int);
    } else {
        second_str = apr_psprintf(ptemp, "%d", second_int);
    }

    return apr_psprintf(ptemp, "%d-%s-%s %s:%s:%s", year_int, month_str, day_str, hour_str, 
            minute_str, second_str);
}

static void printf_notsuffix_result(cparser_context_t *context, webserver_t *wb)
{
    int num = 0;

    suffix_t *old_suffix;

    list_for_each_entry(old_suffix, &wb->cfg.suffix_head, list, suffix_t) {
        cparser_printf(context, "  %-3d    %s\n", ++num, old_suffix->suffix);
    }
}

static void printf_tamper_result(cparser_context_t *context, webserver_t *wb)
{
    apr_pool_t *ptemp;
    unsigned char *encrypt_password;

    apr_pool_create(&ptemp, g_global_pool);
    apr_pool_tag(ptemp, "ptemp");

    encrypt_password = tripleDes(ptemp, (const unsigned char *)(wb->cfg.password), 
                               get_3des_key(ptemp, PASSWORD_KEY), 
                               get_3des_vector(ptemp, PASSWORD_KEY),
                               DES_ENCRYPT);

    cparser_printf(context, "----------------------------------------------------\n");
    cparser_printf(context, "Tamper name: %s\n", wb->cfg.wsname);
    cparser_printf(context, " Monitor:           %s\n", monitor_type[wb->cfg.enable]);
    cparser_printf(context, " Monitor-File-Size: %d (KiB)\n", UNIT_CONVERT_B_TO_KB(wb->cfg.maxfilesize));
    cparser_printf(context, " Monitor-Folder configuration as follows:\n");
    cparser_printf(context, "  Depth:            %d\n", wb->cfg.depth);
    cparser_printf(context, "  Root-Folder:      %d\n", wb->cfg.root_interval);
    cparser_printf(context, "  Other-Interval:   %d\n", wb->cfg.other_interval);
    
    cparser_printf(context, " Monitor-File-Type-Excluded configuration as follows:\n");
    cparser_printf(context, "  No.    File-Type\n");
    printf_notsuffix_result(context, wb);

    cparser_printf(context, " Connect configuration as follows:\n");
    cparser_printf(context, "  Protocol:     %s\n", 
        strlen(wb->cfg.prtcl_name) ? wb->cfg.prtcl_name : "--");
    cparser_printf(context, "  Server-IP:    %s\n", strlen(wb->cfg.host) ? wb->cfg.host : "--");
    cparser_printf(context, "  Host:         --\n");
    cparser_printf(context, "  Port:         %d\n", wb->cfg.prtcl_port);
    cparser_printf(context, "  Username:     %s\n", 
        strlen(wb->cfg.username) ? wb->cfg.username : "--");
    cparser_printf(context, "  Password:     cipher-text %s\n", encrypt_password ? encrypt_password : (unsigned char *)"--");
    cparser_printf(context, "  Status:       %s\n", 
        wb->conect_status ? "Succ" : "Fail");
    
    cparser_printf(context, " Restore-Mode:  %s\n", restore_type[wb->cfg.isautorestore]);
    cparser_printf(context, " Disk-Size:     %d (MiB)\n", UNIT_CONVERT_B_TO_MB(wb->cfg.disksize));
    cparser_printf(context, " Document-Root: %s\n", 
        strlen(wb->cfg.server_root) ? wb->cfg.server_root : "--");

    cparser_printf(context, " File Statistic as follows:\n");
    cparser_printf(context, "  Total:   %d\n", wb->totalnum);
    cparser_printf(context, "  Backup:  %d\n", wb->backupnum);
    cparser_printf(context, "  Tamper:  %d\n", wb->changednum);
    
    cparser_printf(context, " Email:         %s\n", 
        strlen(wb->cfg.email) ? wb->cfg.email : "--");
    cparser_printf(context, " Description:   %s\n", 
        strlen(wb->cfg.description) ? wb->cfg.description : "--");    

    apr_pool_destroy(ptemp);
}

cparser_result_t cparser_cmd_show_tamper_tampername(cparser_context_t *context,
    char **tampername_ptr)
{
    char *pwsname;
    webserver_t *wb;
    struct list_head *pos;
    char buf[COMMAND_LEN_MAX];

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
       return CPARSER_OK;
    } else {
        if (tampername_ptr != NULL && *tampername_ptr != NULL) {
            /* 显示单台防篡改配置 */
            pwsname = *tampername_ptr;
            pthread_mutex_lock(&list_mutex);
            wb = (webserver_t *)find_webserver(&webserver_listhead, pwsname);
            if (wb) {
                printf_tamper_result(context, wb);
            } else {
                cparser_printf(context, "webserver %s does not esist.\n", pwsname);
            }
            pthread_mutex_unlock(&list_mutex);
            snprintf(buf, COMMAND_LEN_MAX, "show tamper %s", *tampername_ptr);
            admin_log_process(context, buf);
        } else {
            pthread_mutex_lock(&list_mutex);
            list_for_each(pos, &webserver_listhead) {
                wb = list_entry(pos, webserver_t, list);
                if (wb) {
                    printf_tamper_result(context, wb);
                }
            }
            pthread_mutex_unlock(&list_mutex);
            snprintf(buf, COMMAND_LEN_MAX, "show tamper");
            admin_log_process(context, buf);
        }
    }

    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_tamper_disk(cparser_context_t *context)
{
    webserver_t *wb;
    struct list_head *pos;
    char buf[COMMAND_LEN_MAX];
    int num = 0;

    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    } else {
        pthread_mutex_lock(&list_mutex);
        cparser_printf(context, "--------------------------------------\n");
        cparser_printf(context, "Total disk size: %llu (MiB)\n", UNIT_CONVERT_B_TO_MB(total_disksize)); 
        cparser_printf(context, "Left  disk size: %llu (MiB)\n", UNIT_CONVERT_B_TO_MB(left_disksize));
        cparser_printf(context, "Tamper disk size configuration as follows:\n");
        cparser_printf(context, " No.    Tamper-Name         Total(MiB)    Used(MiB)     Left(MiB)\n");
        list_for_each(pos, &webserver_listhead) {
            wb = list_entry(pos, webserver_t, list);
            if (wb) {
                cparser_printf(context, " %-3d    %-16s    %-9llu     %-9llu     %-9llu\n", 
                    ++num, wb->cfg.wsname, 
                    UNIT_CONVERT_B_TO_MB(wb->cfg.disksize), 
                    UNIT_CONVERT_B_TO_MB(wb->backupsize), 
                    UNIT_CONVERT_B_TO_MB(wb->cfg.disksize) - UNIT_CONVERT_B_TO_MB(wb->backupsize));
            }
        }

        snprintf(buf, COMMAND_LEN_MAX, "show tamper-disk");
        admin_log_process(context, buf);
        pthread_mutex_unlock(&list_mutex);
    }

    return CPARSER_OK;
}

static void printf_tamperlog_result(cparser_context_t *context, apr_pool_t *ptemp, 
             apr_dbd_results_t **res)
{
    int rv;
    apr_dbd_row_t *row;
    int nrows, ncols;
    int i, j;
    const char *entry;
    apr_time_t time_int;
    char tam_time[64];
    char *tamper_name, *server_ip, *type, *file;
    char format[10] = { 0 };

    cparser_printf(context, "--------------------------------------------------------"
        "-----------------------------\n");
    cparser_printf(context, FORMATE_TAMPERLOG_STRING, "Tamper-Name", "Server-IP", "Tamper-Type", 
        "Tamper-Time", "Tamper-File");

    nrows = apr_dbd_num_tuples(ap_logdb_driver, *res);
    row = NULL;
    for (i = 1; i <= nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, i);
        if (rv == 0) {
            memset(tam_time, 0, 64);
            tamper_name = NULL;
            server_ip  = NULL;
            type  = NULL;
            file  = NULL;
            ncols = apr_dbd_num_cols(ap_logdb_driver, *res);
            for (j = 0; j < ncols; j++) {
                entry = apr_dbd_get_entry(ap_logdb_driver, row, j);
                switch(j) {
                case 0:
                    /* tamper name */
                    tamper_name = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 1:
                    /* server-ip */
                    server_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 2:
                    /* Detect-Time */
                    break;
                case 3:
                    /* Tamper-Time */
                    time_int = apr_atoi64(entry);
                    apr_ctime(tam_time, time_int * APR_USEC_PER_SEC); 
                    break;
                case 4:
                    /* Version */
                    break;
                case 5:
                    /* Action */
                    break;
                case 6:
                    /* behaviour */  
                    /* 从数据库中获取的action是utf-8编码的，每个汉字3个字节，
                     * 而在printf的时候确是按照每个汉字2个字节打印，会减少1/3 
                     */
                    sprintf(format, "%%-%ds", 11 + (strlen(entry) / 3) );
                    type = apr_psprintf(ptemp, format, entry); 
                    break;
                case 7:
                    break;
                case 8:
                    /* file */
                    file= apr_psprintf(ptemp, "%s", entry);
                    break;
                default:
                    break;
                }
            }
            cparser_printf(context, FORMATE_TAMPERLOG_STRING_UTF8, tamper_name ? tamper_name : "--", 
                server_ip ? server_ip : "--", type ? type : "--", 
                tam_time[0] ? tam_time : "--", file ? file : "--");
        }
    }
}

static cparser_result_t cparser_tamper_log_show(cparser_context_t *context, char *p_wsname, 
                            int flag, uint32_t recent_hours, uint32_t start_year, uint32_t start_month, 
                            uint32_t start_day, uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
                            uint32_t end_year, uint32_t end_month, uint32_t end_day, uint32_t end_hour, 
                            uint32_t end_min, uint32_t end_sec)
{
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    webserver_t *wb;
    char buf[COMMAND_LEN_MAX];
    int rv; 
    apr_dbd_results_t *res;
    apr_pool_t *ptemp;
    char *start_time;
    char *end_time;

    apr_pool_create(&ptemp, g_global_pool);
    apr_pool_tag(ptemp, "ptemp");
    
    if (p_wsname == NULL || p_wsname[0] == '\0') {
        if (flag == 0) {
            sprintf(sql_statement, "select * from tamper_log_table;");
            snprintf(buf, COMMAND_LEN_MAX, "show tamper-log all");
        } else if (flag == 1) {
            sprintf(sql_statement, "select * from tamper_log_table where "
                "UNIX_TIMESTAMP() - detect_time <= %d;", recent_hours * 3600);            
            snprintf(buf, COMMAND_LEN_MAX, "show tamper-log all recent %d", recent_hours);
        } else if (flag == 2) {
            start_time = format_time(ptemp, start_year, start_month, start_day, start_hour, start_min, start_sec);
            end_time = format_time(ptemp, end_year, end_month, end_day, end_hour, end_min, end_sec);
            sprintf(sql_statement, "select * from tamper_log_table where "
                "detect_time between UNIX_TIMESTAMP('%s') and UNIX_TIMESTAMP('%s');",
                start_time, end_time);
            snprintf(buf, COMMAND_LEN_MAX, 
                "show tamper-log all start-time %d %d %d %d %d %d end-time %d %d %d %d %d %d", 
                start_year, start_month, start_day, 
                start_hour, start_min, start_sec, end_year, end_month, 
                end_day, end_hour, end_min, end_sec);
        }
        
        goto __show_result;
    }

    pthread_mutex_lock(&list_mutex);
    wb = (webserver_t *)find_webserver(&webserver_listhead, p_wsname);
    pthread_mutex_unlock(&list_mutex);
    if (wb == NULL) {
        goto  __exit;
    }

    if (flag == 0) {
        sprintf(sql_statement, "select * from tamper_log_table where wsname = '%s';", p_wsname);
        snprintf(buf, COMMAND_LEN_MAX, "show tamper-log web-tamper %s", p_wsname);
    } else if (flag == 1) {
        sprintf(sql_statement, "select * from tamper_log_table where wsname = '%s' and "
            " UNIX_TIMESTAMP() - detect_time <= %d;",
            p_wsname, recent_hours * 3600);
        snprintf(buf, COMMAND_LEN_MAX, "show tamper-log web-tamper %s recent %d", p_wsname, recent_hours);
    } else if (flag == 2) {
        start_time = format_time(ptemp, start_year, start_month, start_day, start_hour, start_min, start_sec);
        end_time = format_time(ptemp, end_year, end_month, end_day, end_hour, end_min, end_sec);
        sprintf(sql_statement, "select * from tamper_log_table where wsname = '%s' and "
            "detect_time between UNIX_TIMESTAMP('%s') and UNIX_TIMESTAMP('%s');", p_wsname,
            start_time, end_time);
        snprintf(buf, COMMAND_LEN_MAX, 
            "show tamper-log web-tamper %s start-time %d %d %d %d %d %d end-time %d %d %d %d %d %d", 
            p_wsname, start_year, start_month, start_day, 
            start_hour, start_min, start_sec, end_year, end_month, 
            end_day, end_hour, end_min, end_sec);
    }

__show_result:
    res = NULL;
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "show tamper log failure");
        goto __exit;    
    }

    printf_tamperlog_result(context, ptemp, &res); 
    admin_log_process(context, buf);
    
__exit:
    apr_pool_destroy(ptemp);     
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_tamper_log_all(cparser_context_t *context)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    return cparser_tamper_log_show(context, NULL, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

cparser_result_t cparser_cmd_show_tamper_log_all_recent_hours(cparser_context_t *context,
    uint32_t *hours_ptr)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    if (hours_ptr == NULL) {
        return CPARSER_NOT_OK;
    }  

    return cparser_tamper_log_show(context, NULL, 1, *hours_ptr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

cparser_result_t cparser_cmd_show_tamper_log_all_start_time_start_year_start_month_start_day_start_hour_start_min_start_sec_end_time_end_year_end_month_end_day_end_hour_end_min_end_sec(cparser_context_t *context,
    uint32_t *start_year_ptr, uint32_t *start_month_ptr, uint32_t *start_day_ptr, uint32_t *start_hour_ptr,
    uint32_t *start_min_ptr, uint32_t *start_sec_ptr, uint32_t *end_year_ptr, uint32_t *end_month_ptr,
    uint32_t *end_day_ptr, uint32_t *end_hour_ptr, uint32_t *end_min_ptr, uint32_t *end_sec_ptr)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    if (!start_year_ptr || !start_month_ptr || !start_day_ptr || !start_hour_ptr || !start_min_ptr
          || !start_sec_ptr || !end_year_ptr || !end_month_ptr || !end_day_ptr || !end_hour_ptr 
          || !end_min_ptr || !end_sec_ptr) {
        return CPARSER_NOT_OK;
    }

    return cparser_tamper_log_show(context, NULL, 2, -1, *start_year_ptr, *start_month_ptr, 
         *start_day_ptr, *start_hour_ptr, *start_min_ptr, *start_sec_ptr, *end_year_ptr, 
         *end_month_ptr, *end_day_ptr, *end_hour_ptr, *end_min_ptr, *end_sec_ptr);
}

cparser_result_t cparser_cmd_show_tamper_log_tamper_name(cparser_context_t *context,
    char **name_ptr)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    if (name_ptr == NULL || *name_ptr == NULL) {
        return CPARSER_NOT_OK;
    }

    return cparser_tamper_log_show(context, *name_ptr, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

cparser_result_t cparser_cmd_show_tamper_log_tamper_name_recent_hours(cparser_context_t *context,
    char **name_ptr, uint32_t *hours_ptr)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    if (name_ptr == NULL || *name_ptr == NULL || hours_ptr == NULL) {
        return CPARSER_NOT_OK;
    }

    return cparser_tamper_log_show(context, *name_ptr, 1, *hours_ptr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
}

cparser_result_t cparser_cmd_show_tamper_log_tamper_name_start_time_start_year_start_month_start_day_start_hour_start_min_start_sec_end_time_end_year_end_month_end_day_end_hour_end_min_end_sec(cparser_context_t *context,
    char **name_ptr, uint32_t *start_year_ptr, uint32_t *start_month_ptr, uint32_t *start_day_ptr, uint32_t *start_hour_ptr,
    uint32_t *start_min_ptr, uint32_t *start_sec_ptr, uint32_t *end_year_ptr, uint32_t *end_month_ptr,
    uint32_t *end_day_ptr, uint32_t *end_hour_ptr, uint32_t *end_min_ptr, uint32_t *end_sec_ptr)
{
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    if (name_ptr == NULL || *name_ptr == NULL || !start_year_ptr || !start_month_ptr || !start_day_ptr 
            || !start_hour_ptr || !start_min_ptr || !start_sec_ptr || !end_year_ptr || !end_month_ptr
            || !end_day_ptr || !end_hour_ptr || !end_min_ptr || !end_sec_ptr) {
        return CPARSER_NOT_OK;
    }
    
    return cparser_tamper_log_show(context, *name_ptr, 2, -1, *start_year_ptr, *start_month_ptr,
        *start_day_ptr, *start_hour_ptr, *start_min_ptr, *start_sec_ptr,*end_year_ptr, *end_month_ptr,
    *end_day_ptr, *end_hour_ptr, *end_min_ptr, *end_sec_ptr);
}

int show_adminlog_init(apr_pool_t *p)
{   
    int rv;
    
    /* 分配子池 */
    rv = apr_pool_create(&g_padminlog, p);
    if (rv) {
        return -1;
    }
    apr_pool_tag(g_padminlog, "g_adminlog");

    return 0;
}

static void printf_adminlog_result(cparser_context_t *context, apr_pool_t *ptemp, apr_dbd_results_t **res)
{
    int rv;
    apr_dbd_row_t *row;
    int nrows, ncols;
    int i, j;
    const char *entry;
    apr_time_t time_int;
    char time_str[64];
    char *user_name, *login_ip, *tty, *app, *command;

    cli_printf_info(context, FORMATE_ADMINLOG_STRING, 
        "Time", "User-Name", "Login-IP", "Tty", "Application", "Command");
    
    nrows = apr_dbd_num_tuples(ap_logdb_driver, *res);
    row = NULL;
#if APU_HAVE_SQLITE3
    for (i = 0; i < nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, -1);
#elif APU_HAVE_MYSQL
    for (i = 1; i <= nrows; i++) {
        rv = apr_dbd_get_row(ap_logdb_driver, ptemp, *res, &row, i);
#endif
        if (rv == 0) {
            ncols = apr_dbd_num_cols(ap_logdb_driver, *res);
            for (j = 0; j < ncols; j++) {
                entry = apr_dbd_get_entry(ap_logdb_driver, row, j);
                switch(j) {
                case 0:
                    /* 时间 */
                    time_int = apr_atoi64(entry);
                    apr_ctime(time_str, time_int * APR_USEC_PER_SEC);
                    break;
                case 1:
                    /* ip */
                    login_ip = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 2:
                    /* 用户名 */
                    user_name = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 3:
                    /* tty */
                    tty = apr_psprintf(ptemp, "%s", entry); 
                    break;     
                case 4:
                    /* command */
                    command = apr_psprintf(ptemp, "%s", entry);
                    break;
                case 5:
                    /* app */
                    app = apr_psprintf(ptemp, "%s", entry); 
                    break;
                default:
                    break;
                }
            }

            cli_printf_info(context, FORMATE_ADMINLOG_STRING, 
                time_str, user_name, login_ip, tty, app, command);
        }
    }
}

static char *format_adminlog_sql_statement(apr_pool_t *ptemp, int flag, uint32_t recent_hours,
                uint32_t start_year, uint32_t start_month, uint32_t start_day, 
                uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
                uint32_t end_year, uint32_t end_month, uint32_t end_day, 
                uint32_t end_hour, uint32_t end_min, uint32_t end_sec)
{
    char *sql_statement;
    char *start_time;
    char *end_time;
    char *temp;

        /* 如果没有输入查询条件，则查询所有 */
    sql_statement = apr_psprintf(ptemp, "select * from admin_log_table where app_type = 'anti-tamper'");

    /* 时间条件 */
    if (flag == 1) {
#if APU_HAVE_SQLITE3
        temp = apr_psprintf(ptemp, "and julianday('now', 'localtime') * 86400 - julianday(time) * 86400 <= %d ", 
            recent_hours * 3600);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and UNIX_TIMESTAMP() - time <= %d ", recent_hours * 3600);
#endif
        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    } else if (flag == 2) {
        start_time = format_time(ptemp, start_year, start_month, start_day, start_hour, start_min, start_sec);
        end_time = format_time(ptemp, end_year, end_month, end_day, end_hour, end_min, end_sec);
        
#if APU_HAVE_SQLITE3 
        temp = apr_psprintf(ptemp, "and julianday(time) * 86400 between julianday('%s') * 86400 "
                "and julianday('%s') * 86400 ", start_time, end_time);
#elif APU_HAVE_MYSQL
        temp = apr_psprintf(ptemp, "and time between UNIX_TIMESTAMP('%s') "
            "and UNIX_TIMESTAMP('%s')", start_time, end_time);
#endif

        sql_statement = apr_pstrcat(ptemp, sql_statement, temp, NULL);
    }

    sql_statement = apr_pstrcat(ptemp, sql_statement, ";", NULL);  
    return sql_statement;
}


void show_adminlog_content(cparser_context_t *context, int flag, uint32_t recent_hours, uint32_t start_year, uint32_t start_month, 
        uint32_t start_day, uint32_t start_hour, uint32_t start_min, uint32_t start_sec,
        uint32_t end_year, uint32_t end_month, uint32_t end_day, uint32_t end_hour, 
        uint32_t end_min, uint32_t end_sec)
{
    int rv;  
    apr_dbd_results_t *res;
    apr_pool_t *ptemp;
    char *sql_statement;
    char buf[COMMAND_LEN_MAX];
        
    apr_pool_create(&ptemp, g_padminlog);
    apr_pool_tag(ptemp, "ptemp");

    /* 构建管理日志语句 */
    if (flag == 0) {
        sprintf(buf, "show admin-log");    
    } else if (flag == 1) {
        sprintf(buf, "show admin-log recent %d", recent_hours);
    } else if (flag == 2) {
        sprintf(buf, "show admin-log start-time %d %d %d %d %d %d end-time %d %d %d %d %d %d", 
                start_year, start_month, start_day, 
                start_hour, start_min, start_sec, end_year, end_month, 
                end_day, end_hour, end_min, end_sec);
    } 

    /* 构建sql语句 */
    sql_statement = format_adminlog_sql_statement(ptemp, flag, recent_hours, start_year, start_month, 
        start_day, start_hour, start_min, start_sec, end_year, end_month, end_day, end_hour, 
        end_min, end_sec);

    if (sql_statement == NULL) {
        goto __exit;
    }

     /* 数据库查询 */
    res = NULL;

#if APU_HAVE_SQLITE3
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 0);
#elif APU_HAVE_MYSQL
    rv = apr_dbd_select(ap_logdb_driver, ptemp, ap_logdb_handle, &res, sql_statement, 1);
#endif
    if (rv != APR_SUCCESS) {
        TAMPER_LOG_WRITE(PE_LOG_FATAL, "show admin log failure");
        goto __exit;    
    }
    
    /* 管理日志打印 */
    printf_adminlog_result(context, ptemp, &res);
    admin_log_process(context, buf);
__exit:
    apr_pool_destroy(ptemp);  
    return;
}

cparser_result_t cparser_cmd_show_admin_log(cparser_context_t *context)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    }
    
    show_adminlog_content(context, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_admin_log_recent_hours(cparser_context_t *context, uint32_t *hours_ptr)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    }
    
    show_adminlog_content(context, 1, *hours_ptr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0 ,0);
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_admin_log_start_time_start_year_start_month_start_day_start_hour_start_min_start_sec_end_time_end_year_end_month_end_day_end_hour_end_min_end_sec(cparser_context_t *context,    
    uint32_t *start_year_ptr, uint32_t *start_month_ptr, uint32_t *start_day_ptr, uint32_t *start_hour_ptr, uint32_t *start_min_ptr, uint32_t *start_sec_ptr, uint32_t *end_year_ptr, uint32_t *end_month_ptr, 
    uint32_t *end_day_ptr, uint32_t *end_hour_ptr, uint32_t *end_min_ptr, uint32_t *end_sec_ptr)
{
    if (context->parser->mode != CPARSER_MODE_CONFIG) { 
        return CPARSER_OK;
    }
    
    show_adminlog_content(context, 2, 0, *start_year_ptr, *start_month_ptr, *start_day_ptr, 
                *start_hour_ptr, *start_min_ptr, *start_sec_ptr, *end_year_ptr, *end_month_ptr, 
                *end_day_ptr, *end_hour_ptr, *end_min_ptr, *end_sec_ptr);
    
    return CPARSER_OK;
}

cparser_result_t cparser_cmd_show_running_config(cparser_context_t *context)
{
    char buf[COMMAND_LEN_MAX];
    
    if (context == NULL) {
        return CPARSER_NOT_OK;
    }
    
    if (context->parser->mode != CPARSER_MODE_CONFIG) {
        return CPARSER_OK;
    }

    snprintf(buf, COMMAND_LEN_MAX, "show running-config");
    admin_log_process(context, buf);
    return cparser_running_conf_cmd(context->parser);
}

/**
 * cli_thread -  cli线程
 * @param arg: NULL
 *
 * cli线程
 *
 * @returns
 *     失败: NULL
 */
void *cli_thread(void *arg)
{
    cparser_t parser;
    char config_file[1024] = { 0 };
    int debug = 0;
    int cli_io_type = IO_SOCKET_UNIX;

    snprintf(g_cli_prompt, MAX_CLI_PROMPT_LEN, "%s", DEFAULT_CLI_PROMPT);
    
    memset(&parser, 0, sizeof(parser));
    strncat(config_file, ROOT_PATH, 1024);
    strncat(config_file, "/conf/cli.conf", 1024);

    /* 挂show树到全局命令树中 */
    cparser_global_add_tree(&cparser_show_root);
    /* 挂全局命令树到主树中 */
    cparser_hang_global_tree(&cparser_root);

    parser.cfg.root = &cparser_root;
    /* 命令辅助键（自动补充完整命令） */
    parser.cfg.ch_complete = '\t';
    /*
     * Instead of making sure the terminal setting of the target and
     * the host are the same. ch_erase and ch_del both are treated
     * as backspace.
     */

    /* 定义删除键 */
    parser.cfg.ch_erase = '\b';
    parser.cfg.ch_del = 127;
    /* 定义帮助键 */
    parser.cfg.ch_help = '?';
    /* cli parser测试专用 */
    parser.cfg.flags = (debug ? CPARSER_FLAGS_DEBUG : 0);
    snprintf(parser.cfg.prompt, CPARSER_MAX_PROMPT, "%s> ", g_cli_prompt);
    /* 定义保存配置信息的默认文件 */
    strcpy(parser.default_conf_file, config_file);
    /* 定义调试信息输出终端 */
    parser.cfg.fd = STDOUT_FILENO;
    parser.mode = 0;
    parser.fp = NULL;

    if (!TEMPER_BACKGROUND_RUN && cli_io_type == IO_TERM) {
        parser.cfg.io_type = IO_TERM;
    } else if (cli_io_type == IO_SOCKET_UNIX) {
        /* 定义信息输入输出所用的io接口类型 */
        parser.cfg.io_type = IO_SOCKET_UNIX;
        /* 定义io类型为unixdomain通信时所用的套接字路径 */
        parser.cfg.su_path = "/tmp/webtamper.socket";
        parser.cfg.admin_log_fn = admin_log_process;
    } else {
        syslog(LOG_ERR, "Cli io type error!\n");
        exit(0);
    }

    /* 定义操作系统相关的IO接口 */
    cparser_io_config(&parser);
    /* 初始化解析器 */
    if (CPARSER_OK != cparser_init(&parser.cfg, &parser)) {
        printf("Fail to initialize parser.\n");
        return NULL;
    }
    if (config_file && access(config_file, R_OK) == 0) {
        (void)cparser_load_cmd(&parser, config_file);
    }
    /* 启动解析器 */
    fflush(stdin);
    cparser_run(&parser);
    printf("cli done\n");
    
    return NULL;
}
