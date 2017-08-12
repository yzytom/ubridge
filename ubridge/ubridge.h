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

#ifndef UBRIDGE_H_
#define UBRIDGE_H_

#include <stdlib.h>
#include <errno.h>

#define HAVE_REMOTE

#include <pcap.h>

#include "nio.h"
#include "packet_filter.h"

#define NAME          "ubridge"
#define VERSION       "0.9.12"
#define CONFIG_FILE   "ubridge.ini"

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE  1
#endif

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)
typedef struct {
	char *hypervisor_ip_address;
	int hypervisor_tcp_port;
} run_hypervisor_t;
typedef struct {
	pcap_t *fd;
	pcap_dumper_t *dumper;
	HANDLE lock;
} pcap_capture_t;

typedef struct bridge {
	char *name;
	int running;
	HANDLE source_tid;
	HANDLE destination_tid;
	nio_t *source_nio;
	nio_t *destination_nio;
	pcap_capture_t *capture;
	packet_filter_t *packet_filters;
	volatile struct bridge *next;
} bridge_t;

volatile bridge_t *bridge_list;
extern volatile  HANDLE global_lock;
volatile BOOL* hypervisor_running;
extern volatile int debug_level;

void ubridge_reset();
DWORD WINAPI source_nio_listener(bridge_t *data);
DWORD WINAPI destination_nio_listener(bridge_t *data);

#endif /* !UBRIDGE_H_ */
static BOOL WINAPI ConsoleHandler(DWORD CEvent);
static void display_network_devices(void);
static BOOL WINAPI ConsoleIO(HANDLE handle_in);
static void changedllpath();
void kill_thread(HANDLE tid);