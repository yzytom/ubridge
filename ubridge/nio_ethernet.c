/*
 *   This file is part of ubridge, a program to bridge network interfaces
 *   to UDP tunnels.
 *
 *   Copyright (C) 2015 GNS3 Technologies Inc.
 *
 *   ubridge is free software: you can redistribute it and/or modify it
 *   under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   ubridge is distributed in the hope that it will be useful, but
 *   WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>

#include "ubridge.h"
#include "nio_ethernet.h"

/* Open an Ethernet interface using PCAP */
static pcap_t *nio_ethernet_open(char *device)
{
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   pcap_t *p;

   /* Timeout is 10ms */
   if (!(p = pcap_open_live(device, 65535, TRUE, 10, pcap_errbuf)))
      goto pcap_error;

   pcap_setdirection(p,PCAP_D_INOUT);
   return p;

 pcap_error:
   fprintf(stderr, "nio_ethernet_open: unable to open device '%s': %s\n", device, pcap_errbuf);
   return NULL;
}

static void nio_ethernet_free(nio_ethernet_t *nio_ethernet)
{
   pcap_close(nio_ethernet->pcap_dev);
}

static SSIZE_T nio_ethernet_send(nio_ethernet_t *nio_ethernet, void *pkt, SSIZE_T pkt_len)
{
	SSIZE_T res = pcap_sendpacket(nio_ethernet->pcap_dev, (u_char *)pkt, pkt_len);
   if (res == -1)
      fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(nio_ethernet->pcap_dev));
   return (res);
}

static SSIZE_T nio_ethernet_recv(nio_ethernet_t *nio_ethernet, void *pkt, SSIZE_T max_len)
{
   struct pcap_pkthdr *pkt_info;
   const u_char *pkt_data;
   SSIZE_T rlen;
   int res;

   timedout:
   res = pcap_next_ex(nio_ethernet->pcap_dev, &pkt_info, &pkt_data);
   if (res == 0) {
      /* Timeout elapsed */
      goto timedout;
    }

   if(res == -1) {
      fprintf(stderr, "pcap_next_ex: %s\n", pcap_geterr(nio_ethernet->pcap_dev));
      return (-1);
   }

   rlen = m_min(max_len, pkt_info->caplen);
   memcpy(pkt, pkt_data, rlen);
   return (rlen);
}

/* Create a new NIO Ethernet (using PCAP) */
nio_t *create_nio_ethernet(char *dev_name)
{
   nio_ethernet_t *nio_ethernet;
   nio_t *nio;

   if (!(nio = create_nio()))
      return NULL;

   nio_ethernet = &nio->u.nio_ethernet;

   if (!(nio_ethernet->pcap_dev = nio_ethernet_open(dev_name))) {
      free_nio(nio);
      return NULL;
   }

   printf("Ethernet interface %s\n", dev_name);

   nio->type = NIO_TYPE_ETHERNET;
   nio->send = (void *)nio_ethernet_send;
   nio->recv = (void *)nio_ethernet_recv;
   nio->free = (void *)nio_ethernet_free;
   nio->dptr = &nio->u.nio_ethernet;
   return nio;
}
