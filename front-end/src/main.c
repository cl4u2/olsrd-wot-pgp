/*
 * OLSR ad-hoc routing table management protocol GUI front-end
 * Copyright (C) 2003 Andreas T�nnesen (andreto@ifi.uio.no)
 *
 * This file is part of olsrd-unik.
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
 * along with olsrd-unik; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include "common.h"
#include "main.h"

int
main (int argc, char *argv[])
{
#ifdef WIN32
  WSADATA WsaData;
#endif
  GtkWidget *main_window;

#ifdef WIN32
  if (WSAStartup(0x0202, &WsaData))
    {
      fprintf(stderr, "Could not initialize WinSock.\n");
      exit(1);
    }
#endif

  gtk_init (&argc, &argv);

  init_nodes();

  freeze_packets = 1;
  display_dec = 1;

  /* "Failsafe" values */
  ipversion = AF_INET;
  ipsize = sizeof(struct in_addr);

  main_window = create_main_window ();
  gtk_widget_show (main_window);

  printf("Done building GUI\n");

  memset(&main_addr, 0, sizeof(union olsr_ip_addr));
  memset(&null_addr, 0, sizeof(union olsr_ip_addr));

  /* Terminate signal */
  signal(SIGINT, shutdown_);  

  /* Init node timeout */
  nodes_timeout = NEIGHB_HOLD_TIME_NW;
  init_timer((olsr_u32_t) (nodes_timeout * 1000), &hold_time_nodes);

  ipc_connect();

  add_timeouts();

  gtk_main ();
  return 0;
}



/*
 *Timeouts
 */

int
add_timeouts()
{

  /*
   *Check socket for messages every IPC_INTERVAL
   *milliseconds
   */
  gtk_timeout_add(IPC_INTERVAL, ipc_timeout, NULL);


  /*
   *Time out nodes
   */
  timeouts = 5; /* Wait 5 times befor starting timing out nodes */
  gtk_timeout_add(TOP_HOLD_TIME, time_out_nodes, NULL);


 return 1;
}



gint ipc_timeout(gpointer data)
{

  ipc_read();
  return 1;
}



void
shutdown_(int signal)
{
  printf("Cleaning up...\n");

  if(ipc_close() < 0)
    printf("Could not close socket!\n");

  printf("BYE-BYE!\n");
  exit(signal);
}
