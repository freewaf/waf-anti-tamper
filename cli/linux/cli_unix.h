/*
 * $Id: cli_unix.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#ifndef _CLI_UNIX_H_
#define _CLI_UNIX_H_

#include "apr_pools.h"

#ifndef COMMAND_LEN_MAX
#define COMMAND_LEN_MAX 128
#endif

#define DEFAULT_DEPTH                 50
#define DEFAULT_ROOT_INTERVAL         10
#define DEFAULT_OTHER_INTERVAL        60
#define DEFAULT_MAXFILESIZE           1024
#define DEFAULT_AUTORESTORE           0
#define DEFAULT_DEBUG                 0
#define DEFAULT_DOCUMENT_ROOT         "/"
#define DEFAULT_MONITOR               1
#define DEFAULT_DISKSIZE              200

#define cli_printf_info(context, format, args...) cparser_printf(context, format, ##args)

/**
 * cli_thread -  cli线程
 * @param arg: NULL
 *
 * cli线程
 *
 * @returns
 *     失败: NULL
 */

extern void *cli_thread(void *arg);

int show_adminlog_init(apr_pool_t *p);

#endif

