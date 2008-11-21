/*
 * OLSR ad-hoc routing table management protocol GUI front-end
 * Copyright (C) 2003 Andreas Tonnesen (andreto@ifi.uio.no)
 *
 * This file is part of olsr.org.
 *
 * uolsrGUI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * uolsrGUI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with olsr.org; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#include <gdk/gdk.h>
#include <gdk/gdkkeysyms.h>


GtkWidget *net_label;
GtkWidget *info_label;
GtkTextBuffer *textBuffer;
GtkWidget *connect_button;
GtkWidget *packet_list;
GtkWidget *packet_content_list;
GtkWidget *packet_button;
GtkWidget *packet_disp_button;
GtkWidget *node_list;
GtkWidget *mid_list;
GtkWidget *mpr_list;
GtkWidget *hna_list;
GtkWidget *route_list;


void
fill_clist(GtkCList *);


void selection_made( GtkWidget      *clist,
                     gint            row,
                     gint            column,
		     GdkEventButton *event,
                     gpointer        data );


void
set_net_info_connecting();

void
column_clicked_callback(GtkWidget *,gint);


void
connect_callback( GtkWidget *widget,
		  gpointer   data );

void
packet_callback( GtkWidget *widget,
		  gpointer   data );

void
packet_disp_callback( GtkWidget *widget,
		  gpointer   data );


void
packet_selection(GtkWidget *clist, gint row, gint column, GdkEventButton *event, gpointer data);


void
node_selection(GtkWidget *clist, gint row, gint column, GdkEventButton *event, gpointer data);


void
gui_shutdown(GtkObject *, gpointer);
