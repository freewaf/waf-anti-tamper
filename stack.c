/*
 * $Id: stack.c 2786 2013-07-09 16:42:55 FreeWAF Development Team $
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

#include <stdlib.h>
#include "stack.h"

int stack_isempty(struct stack_s *s)
{
    return s->next == NULL;
}

struct stack_s *stack_create()
{
    struct stack_s *s = (struct stack_s *)malloc(sizeof(struct stack_s));
    if(s == NULL) {
        return NULL;
    }
    
    s->next=NULL;

    return s;
}
void stack_push(struct stack_s *s, addrpair_t pair)
{
    struct stack_s *temp=(struct stack_s *)malloc(sizeof(struct stack_s));
    if(temp == NULL) {
        return;
    }
     
    temp->pair = pair;
    temp->next = s->next;
    s->next=temp;
}
void stack_pop(struct stack_s *s)
{
    struct stack_s *temp;
    
    if(stack_isempty(s)) {
        return;
    }
     
    temp = s->next;
    s->next = s->next->next;
    free(temp);  
}
void stack_makeempty(struct stack_s *s)
{
    if(s == NULL) {
        return;
    }
    
    while(!stack_isempty(s)) {
        stack_pop(s);
    }
}
void stack_destroy(struct stack_s *s)
{
    stack_makeempty(s);
    free(s);
}

addrpair_t stack_top(struct stack_s *s)
{
    addrpair_t temp;

    if(!stack_isempty(s)) {
        return s->next->pair;
    }

    temp.source = NULL;
    temp.dest = NULL;
    temp.parent= NULL;
    
    return temp; 
}

