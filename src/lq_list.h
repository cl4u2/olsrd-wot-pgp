/* 
 * OLSR ad-hoc routing table management protocol
 * Copyright (C) 2004 Thomas Lopatic (thomas@lopatic.de)
 *
 * This file is part of the olsr.org OLSR daemon.
 *
 * olsr.org is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * olsr.org is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with olsr.org; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id: lq_list.h,v 1.1 2004/11/07 17:51:20 tlopatic Exp $
 *
 */

struct list_node
{
  struct list_node *next;
  struct list_node *prev;

  void *data;
};

struct list
{
  struct list_node *head;
  struct list_node *tail;
};

void list_init(struct list *list);

struct list_node *list_get_head(struct list *list);
struct list_node *list_get_tail(struct list *list);

struct list_node *list_get_next(struct list_node *node);
struct list_node *list_get_prev(struct list_node *node);

void list_add_head(struct list *list, struct list_node *node);
void list_add_tail(struct list *list, struct list_node *node);

void list_add_before(struct list *list, struct list_node *pos_node,
                     struct list_node *node);
void list_add_after(struct list *list, struct list_node *pos_node,
                    struct list_node *node);

void list_remove(struct list *list, struct list_node *node);
