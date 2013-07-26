/* Declaration of functions and data types used for MD5 sum computing
   library functions.
   Copyright (C) 1995-1997,1999,2000,2001,2004,2005,2006
      Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 2, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _MD5_H_
#define _MD5_H_

#define DIGEST_ALIGN     4
#define DIGEST_BITS      128
#define DIGEST_HEX_BYTES (DIGEST_BITS / 4)
#define DIGEST_BIN_BYTES (DIGEST_BITS / 8)

extern inline void *md5_value_align(void const *ptr, int  alignment);
extern int md5_generate_value(char *filename, unsigned char *md5_value);

#endif /* md5.h */

