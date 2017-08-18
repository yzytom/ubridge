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
#include <stdlib.h>
#include <signal.h>
#include <string.h>

#include "ubridge.h"
#include "parse.h"
#include "pcap_capture.h"
#include "packet_filter.h"
#include "hypervisor.h"

static char *config_file = CONFIG_FILE;
volatile HANDLE global_lock = (intptr_t)0;
volatile int hypervisor_mode = 0;
static HANDLE hFile_mode;
volatile static BOOL running_file_mode = TRUE;
volatile int debug_level = 0;

static void bridge_nios(nio_t *rx_nio, nio_t *tx_nio, bridge_t *bridge)
{
	SSIZE_T bytes_received, bytes_sent;
	u_char *pkt = malloc(NIO_MAX_PKT_SIZE*sizeof(u_char));
	int drop_packet;

	while (bridge->running == TRUE) {
		// receive from the receiving NIO 
		drop_packet = FALSE;
		bytes_received = nio_recv(rx_nio, pkt, NIO_MAX_PKT_SIZE);
		if (bytes_received == -1) {
			if (errno == ECONNREFUSED || errno == ENETDOWN || errno == NO_ERROR)
				continue;

			perror("recv");
			break;
		}

		if (bytes_received > NIO_MAX_PKT_SIZE) {
			fprintf(stderr, "received frame is %zd bytes (maximum is %d bytes)\n", bytes_received, NIO_MAX_PKT_SIZE);
			continue;
		}

		rx_nio->packets_in++;
		rx_nio->bytes_in += bytes_received;

		if (debug_level > 0) {
			if (rx_nio == bridge->source_nio)
				printf("Received %zd bytes on bridge '%s' (source NIO)\n", bytes_received, bridge->name);
			else
				printf("Received %zd bytes on bridge '%s' (destination NIO)\n", bytes_received, bridge->name);
			if (debug_level > 1)
				dump_packet(stdout, pkt, bytes_received);
		}

		// filter the packet if there is a filter configured 
		if (bridge->packet_filters != NULL) {
			packet_filter_t *filter = bridge->packet_filters;
			packet_filter_t *next;
			while (filter != NULL) {
				if (filter->handler(pkt, bytes_received, filter->data) == FILTER_ACTION_DROP) {
					if (debug_level > 0)
						printf("Packet dropped by packet filter '%s' on bridge '%s'\n", filter->name, bridge->name);
					drop_packet = TRUE;
					break;
				}
				next = filter->next;
				filter = next;
			}
		}

		if (drop_packet == TRUE)continue;

		// dump the packet to a PCAP file if capture is activated 
		pcap_capture_packet(bridge->capture, pkt, bytes_received);

		// send what we received to the transmitting NIO 
		bytes_sent = nio_send(tx_nio, pkt, bytes_received);
		if (bytes_sent == -1) {
			if (errno == ECONNREFUSED || errno == ENETDOWN || errno == NO_ERROR)
				continue;

			perror("send");
			break;
		}

		tx_nio->packets_out++;
		tx_nio->bytes_out += bytes_sent;
	}
	free(pkt);
}

// Source NIO thread 
DWORD WINAPI source_nio_listener(bridge_t  *data)
{
	bridge_t *bridge = data;
	char* name = (char*)malloc(strlen(bridge->name));
	strcpy(name, bridge->name);

	printf("Source NIO listener thread for %s has started\n", name);
	if (bridge->source_nio && bridge->destination_nio)
		// bridges from the source NIO to the destination NIO 
		bridge_nios(bridge->source_nio, bridge->destination_nio, bridge);
	printf("Source NIO listener thread for %s has stopped\n", name);
	return 0;
}

// Destination NIO thread
DWORD WINAPI destination_nio_listener(bridge_t *data)
{
	bridge_t *bridge = data;
	char* name = (char*)malloc(strlen(bridge->name));
	strcpy(name, bridge->name);
	printf("Destination NIO listener thread for %s has started\n", name);
	if (bridge->source_nio && bridge->destination_nio)
		// bridges from the destination NIO to the source NIO
		bridge_nios(bridge->destination_nio, bridge->source_nio, bridge);
	printf("Destination NIO listener thread for %s has stopped\n", name);
	return 0;
}

static void free_bridges(volatile bridge_t* bridge)
{
	volatile bridge_t *next;
	while (bridge != NULL) {
		bridge->running = FALSE;
		if (bridge->name)
			free(bridge->name);
		if (bridge->source_tid) 
			kill_thread(bridge->source_tid);
		if (bridge->destination_tid) 
			kill_thread(bridge->destination_tid);
		free_nio(bridge->source_nio);
		free_nio(bridge->destination_nio);
		next = bridge->next;
		free(bridge);
		bridge = next;
	}
}


static void create_threads(bridge_t *bridge)
{
	while (bridge != NULL) {
		if (bridge->name != NULL) {
			bridge->running = TRUE;
			bridge->source_tid = CreateThread(NULL, 0, source_nio_listener, bridge, 0, NULL);
			if (bridge->source_tid == 0)handle_error_en(GetLastError(), "source_nio_thread_create");
			bridge->destination_tid = CreateThread(NULL, 0, destination_nio_listener, bridge, 0, NULL);
			if (bridge->destination_tid == 0)handle_error_en(GetLastError(), "destination_nio_thread_create");
			bridge = bridge->next;
		}
		break;
	}
}

void ubridge_reset()
{
	free_bridges(bridge_list);
	bridge_list = NULL;
}
static DWORD WINAPI run_hypervisor_thread(run_hypervisor_t p) {
	return run_hypervisor(p.hypervisor_ip_address, p.hypervisor_tcp_port);
}
static void ubridge(char *hypervisor_ip_address, int hypervisor_tcp_port)
{
	HANDLE handle_in = GetStdHandle(STD_INPUT_HANDLE);
	HANDLE hinput = CreateThread(NULL, 0, ConsoleIO, handle_in, 0, NULL);
	if (hypervisor_mode) {
		run_hypervisor(hypervisor_ip_address, hypervisor_tcp_port);
		free_bridges(bridge_list);
		TerminateThread(hinput, 0);
		CloseHandle(hinput);
	}
	else {
		while (running_file_mode) {
			if (!parse_config(config_file, &bridge_list))
				break;
			create_threads(bridge_list);
			hFile_mode= CreateSemaphore(NULL, 0, 1, NULL);
			WaitForSingleObject(hFile_mode, INFINITE);
		}
	}
	return;
}

/* Display all network devices on this host */
static void display_network_devices(void)
{
	char *pcap_errbuf = malloc(PCAP_ERRBUF_SIZE * sizeof(char));
	pcap_if_t *device_list, *device;

	printf("Network device list:\n\n");

	int res = pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &device_list, pcap_errbuf);

	if (res < 0) {
		fprintf(stderr, "PCAP: unable to find device list (%s)\n", pcap_errbuf);
		return;
	}

	for (device = device_list; device; device = device->next)
		printf_s("  %s => %s\n", device->name, device->description ? device->description : "no description");
	printf("\n");
	pcap_freealldevs(device_list);
}

static void print_usage(const char *program_name)
{
	printf("Usage: %s [OPTION]\n"
		"\n"
		"Options:\n"
		"  -h                           : Print this message and exit\n"
		"  -f <file>                    : Specify a INI configuration file (default: %s)\n"
		"  -H [<ip_address>:]<tcp_port> : Run in hypervisor mode\n"
		"  -e                           : Display all available network devices and exit\n"
		"  -d <level>                   : Debug level\n"
		"  -v                           : Print version and exit\n",
		program_name,
		CONFIG_FILE);
}

int main(int argc, char **argv)
{
	hypervisor_running = malloc(sizeof(BOOL));
	int hypervisor_tcp_port = 0;
	char *hypervisor_ip_address=NULL;
	if (argc == 1)exit(EXIT_FAILURE);
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-H") == 0) {
			hypervisor_mode = 1;
			char **addrport = malloc(3 * sizeof(char*));
			char *buf;
			i++;
			if (i == argc)exit(EXIT_FAILURE);
			char *buffer = malloc(strlen(argv[i]));
			memcpy(buffer, argv[i], strlen(argv[i]));
			sscanf(buffer, "%1s", buffer);
			if (strcmp(buffer, "-") == 0) {
				i--;
				continue;
			}
			addrport[0] = strtok_s(argv[i], ":", &buf);
			addrport[1] = strtok_s(NULL, ":", &buf);
			addrport[2] = "\0";
			hypervisor_ip_address = (char*)malloc(strlen(addrport[0]));
			strcpy(hypervisor_ip_address, addrport[0]);
			if (addrport[1] != NULL)
				hypervisor_tcp_port = atoi(addrport[1]);
			continue;
		}
		if (strcmp(argv[i], "-v") == 0) {
			printf("%s version %s\n", NAME, VERSION);
			exit(EXIT_SUCCESS);
		}
		if (strcmp(argv[i], "-h") == 0) {
			print_usage(argv[0]);
			exit(EXIT_SUCCESS);
		}
		if (strcmp(argv[i], "-e") == 0) {
			changedllpath();
			display_network_devices();
			exit(EXIT_SUCCESS);
		}
		if (strcmp(argv[i], "-d") == 0) {
			i++;
			if (i == argc)exit(EXIT_FAILURE);
			char *buffer = malloc(strlen(argv[i]));
			memcpy(buffer, argv[i], strlen(argv[i]));
			sscanf(buffer, "%1s", buffer);
			if (strcmp(buffer, "-") == 0) {
				i--;
				continue;
			}
			debug_level = atoi(argv[i]);
			continue;
		}
		if (strcmp(argv[i], "-f") == 0) {
			i++;
			if (i == argc)exit(EXIT_FAILURE);
			config_file = argv[i];
			continue;
		}
	}
	SetConsoleCtrlHandler(ConsoleHandler, TRUE);
	changedllpath();
	ubridge(hypervisor_ip_address, hypervisor_tcp_port);
	free(hypervisor_ip_address);
	SetDllDirectory(L"");
	WSACleanup();
	return EXIT_SUCCESS;
}
static BOOL WINAPI ConsoleHandler(DWORD CEvent) {
	switch (CEvent) {
	case CTRL_C_EVENT:
		*hypervisor_running = FALSE;
		running_file_mode = FALSE;
		ReleaseSemaphore(hFile_mode, 1, NULL);
		CloseHandle(hFile_mode);
		return TRUE;
		break;
	}
	return FALSE;
}
static BOOL WINAPI ConsoleIO(HANDLE handle_in) {
	INPUT_RECORD keyrec;
	DWORD res;
	BOOL menu = TRUE;
	BOOL isnotInput = TRUE;
	while (menu)
	{
		int getBuff;
		ReadConsoleInput(handle_in, &keyrec, 1, &res);
		switch (keyrec.EventType) {
		case KEY_EVENT: {
			if (keyrec.Event.KeyEvent.bKeyDown && isnotInput) {
				switch (keyrec.Event.KeyEvent.wVirtualKeyCode) {
				case 'Q': {
					menu = FALSE;
					*hypervisor_running = FALSE;
					running_file_mode = FALSE;
					ReleaseSemaphore(hFile_mode,1,NULL);
					CloseHandle(hFile_mode);
					return TRUE;
					break;
				}
				case 'D': {
					int dl;
					isnotInput = FALSE;
					printf("%s", "please input the debug level:");
					while (getBuff = getchar() != '\n' && getBuff != EOF) {}
					scanf("%d", &dl);
					debug_level = dl;
					isnotInput = TRUE;
					break;
				}
				case 'R': {
					if (hypervisor_mode) {
						ubridge_reset();
					}else {
						if (WaitForSingleObject(hFile_mode, 1) == WAIT_TIMEOUT) {
							free_bridges(bridge_list);
							bridge_list = NULL;
							printf("Reloading configuration\n");
							ReleaseSemaphore(hFile_mode, 1, NULL);
							CloseHandle(hFile_mode);
						}
					}
				}
				}
			}
			break;
		}
		}
	}
	return TRUE;
}
static void changedllpath() {
	LPWSTR system32 = (LPWSTR)malloc(MAX_PATH * sizeof(LPWSTR));
	LPWSTR npcap_wpcap_path = (LPWSTR)malloc(MAX_PATH * sizeof(LPWSTR));
	LPWSTR npcap_wpcap_library = (LPWSTR)malloc(MAX_PATH * sizeof(LPWSTR));
	LPWSTR legacy_winpcap_library = (LPWSTR)malloc(MAX_PATH * sizeof(LPWSTR));
	GetSystemDirectory(system32, MAX_PATH);
	lstrcpy(npcap_wpcap_path, system32);
	lstrcat(npcap_wpcap_path, (LPWSTR)L"\\Npcap");
	lstrcpy(npcap_wpcap_library, npcap_wpcap_path);
	lstrcat(npcap_wpcap_library, (LPWSTR)L"\\wpcap.dll");
	lstrcpy(legacy_winpcap_library, system32);
	lstrcat(legacy_winpcap_library, (LPWSTR)L"\\wpcap.dll");
	if (_waccess(npcap_wpcap_library, 0) == 0) {
		SetDllDirectory(npcap_wpcap_path);
		printf("using npcap library!\n");
		return;
	}
	if (_waccess(legacy_winpcap_library, 0) == 0) {
		SetDllDirectory(L"");
		printf("using winpcap library!\n");
	}
	else {
		printf("Can't use npcap and winpcap library!\n");
		exit(EXIT_FAILURE);
	}
}
void kill_thread(HANDLE tid){
	if (WAIT_TIMEOUT == WaitForSingleObject(tid, 2000))
		TerminateThread(tid, 0);
	else
		CloseHandle(tid);
}