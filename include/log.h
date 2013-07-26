/*
 * $Id: log.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
 
#ifndef _PE_LOG_COMM_H_
#define _PE_LOG_COMM_H_

/* 日志级别 */
#define PE_LOG_DEBUG    0
#define PE_LOG_INFO     1
#define PE_LOG_WARN     2
#define PE_LOG_FATAL    3
#define PE_LOG_STOP     4

/* 日志写入宏 */
#define TAMPER_LOG_WRITE(level, ...) pe_log_write(the_log, level, __FILE__, __LINE__, __VA_ARGS__)

/* 日志对象 */
typedef struct pe_log_t pe_log_t;

/* 创建日志对象 */
pe_log_t *pe_log_create(void);

/* 日志对象初始化 */
int pe_log_initialize(pe_log_t *log, const char *name, int level, int fsize);

/* 日志对象写入 */
void pe_log_write(pe_log_t *log, int level, const char * file, int line, const char *fmt, ...);

/* 销毁日志对象 */
void pe_log_destroy(pe_log_t *log);

/* 全局日志对象指针 */
extern pe_log_t *the_log;

#endif /* _PE_LOG_COMM_H_ */

