/*
 * $Id: protocol_sftp.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#ifndef _PROTOCOL_SFTP_H_
#define _PROTOCOL_SFTP_H_

#include "libssh2_config.h"
#include <libssh2.h>
#include <libssh2_sftp.h>

#include "protocol.h"

typedef struct sftp_data_s {
    int sock;
    LIBSSH2_SESSION *session;
    LIBSSH2_SFTP *sftp_session;
    LIBSSH2_SFTP_HANDLE *dir_handle;
    LIBSSH2_SFTP_HANDLE *file_handle;
} sftp_data_t;

/**
 * protocol_sftp_create -  协议数据创建
 *
 * 协议数据创建
 *
 * @returns
 *     成功: 返回协议数据
 *     失败: 返回NULL
 */
extern protocol_data_t *protocol_sftp_create();

/**
 * protocol_sftp_destroy -  协议数据销毁
 * @param type: 协议数据
 *
 * 协议数据销毁
 */
extern void protocol_sftp_destroy(protocol_data_t *type);

#endif

