/*
 * $Id: tamperlog.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include <apr_time.h>
#include <stdio.h>
#include "tamperlog.h"
#include "print.h"
#include "log.h"

#ifndef SQL_STATEMENT_LEN
#define SQL_STATEMENT_LEN 10000
#endif

/* 修改 删除 增加 */
static const char *tamper_type[] = {"E4BFAEE694B9", "E588A0E999A4", "E5A29EE58AA0", NULL};
/* 未恢复 自动恢复 手动恢复 */
static const char *action_type[] = {"E69CAAE681A2E5A48D", "E887AAE58AA8E681A2E5A48D", "E6898BE58AA8E681A2E5A48D", NULL};

/**
 * log_write -  篡改日志接口
 * @param wsname: 防篡改名称
 * @param host: 主机名
 * @param action: 主机名
 *
 * 写防篡改日志
 *
 * @returns
 *     成功: 返回0
 *     失败: 返回-1
 */
void log_write(char *wsname, char *host, const char *action, unsigned long detecttime, unsigned long tampertime, 
        unsigned long restoretime, int version, int beh, char *filename)
{
    int rv;
    char sql_statement[SQL_STATEMENT_LEN] = {0};
    enum RESTORE_TYPE restore_id;

    if (!strcmp(action, "check")) {
        restore_id = RESTORE_DECTET;
    } else if (!strcmp(action, "arestore")) {
        restore_id = RESTORE_AUTO;
    } else if (!strcmp(action, "mrestore")) {
        restore_id = RESTORE_MANUAL;
    } else {
        restore_id = RESTORE_UNKNOWN;
    }

    if (restore_id == RESTORE_DECTET) {
        /* 检测无恢复时间 */
        snprintf(sql_statement, SQL_STATEMENT_LEN, "insert into tamper_log_table values('%s', '%s', "
            "%lu, %lu, %d, x'%s', x'%s', '', '%s');", 
            wsname, host, (unsigned long)detecttime, (unsigned long)tampertime, version, 
            action_type[restore_id], tamper_type[beh], filename);
    } else if (restore_id == RESTORE_AUTO || restore_id == RESTORE_MANUAL) {
        /* 恢复无检测时间 */
        snprintf(sql_statement, SQL_STATEMENT_LEN, "insert into tamper_log_table values('%s', '%s', "
            "'', %lu, %d, x'%s', x'%s', %lu, '%s');", 
            wsname, host, (unsigned long)tampertime, version, 
            action_type[restore_id], tamper_type[beh], (unsigned long)restoretime, filename);  
    } else {    
        return;
    }

    /* 写日志服务器 */
    rv = 0;
    switch (restore_id) {
    case RESTORE_DECTET:
        rv = log_send(sql_statement, 1);
        break;
    case RESTORE_AUTO:
    case RESTORE_MANUAL:
        rv = log_send(sql_statement, 1);
        break;
    default:
        break;
    }

    if (rv < 0) {
        TAMPER_LOG_WRITE(PE_LOG_INFO, "send tamper record to log server failed.");
    }
} 

