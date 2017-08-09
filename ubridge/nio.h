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

#ifndef NIO_H_
#define NIO_H_

#include <stdlib.h>
#include <stdarg.h>
#include <pcap.h>

#define m_min(a,b) (((a) < (b)) ? (a) : (b))

#define NIO_MAX_PKT_SIZE    65535
#define NIO_DEV_MAXLEN      64

enum {
    NIO_TYPE_UDP = 1,
    NIO_TYPE_ETHERNET,
};

typedef struct {
    int fd;
    int local_port;
    int remote_port;
    char *remote_host;
} nio_udp_t;

typedef struct {
    pcap_t *pcap_dev;
} nio_ethernet_t;

typedef struct {
    int fd;
    char *local_filename;
    struct sockaddr remote_sock;
} nio_unix_t;

typedef struct {
    u_int type;
    void *dptr;
    char *desc;

    union {
        nio_udp_t nio_udp;
        nio_ethernet_t nio_ethernet;
    } u;

	SSIZE_T(*send)(void *nio, void *pkt, SSIZE_T len);
	SSIZE_T(*recv)(void *nio, void *pkt, SSIZE_T len);
    void (*free)(void *nio);

	SSIZE_T packets_in, packets_out;
	SSIZE_T bytes_in, bytes_out;

} nio_t;

nio_t *create_nio(void);
void add_nio_desc(nio_t *nio, const char *fmt, ...);
int free_nio(void *data);

SSIZE_T nio_send(nio_t *nio, void *pkt, SSIZE_T len);
SSIZE_T nio_recv(nio_t *nio, void *pkt, SSIZE_T max_len);
void dump_packet(FILE *f_output, u_char *pkt, SSIZE_T len);

#endif /* !NIO_H_ */
