/*
 * $Id: stack.h 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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
#include "tree.h"

typedef struct addrpair_s {
    directory_t *parent;
    char *source;
    char *dest;
    struct stack_s *next;
} addrpair_t;

struct stack_s {
    addrpair_t pair;
    struct stack_s *next;
} ;

extern int stack_isempty(struct stack_s *s);
extern struct stack_s *stack_create();
extern void stack_push(struct stack_s *s, addrpair_t pair);
extern void stack_pop(struct stack_s *s);
extern void stack_makeempty(struct stack_s *s);
extern void stack_destroy(struct stack_s *s);
extern addrpair_t stack_top(struct stack_s *s);

