/* SPDX-License-Identifier: BSD-3-Clause */
/***********************************************************************************************
 * Copyright 2024-2026 Fraunhofer SIT, sponsored by the ELISA and ProSeCA research projects.
 * All rights reserved.
 **********************************************************************************************/

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define TIMEOUT 30U /*in seconds*/

#ifndef NDEBUG
#define PRINT_ERROR() perror(NULL)
#else
#define PRINT_ERROR() ((void)0)
#endif

static const uint32_t PTM_SHUTDOWN = _IOR('P', 2, uint32_t);
static int await_socket(const int socket_fd, const int write, const time_t timeout);
static uint32_t ioctl_to_cmd(const uint32_t ioctlnum);

/*
 * Simple tool for sending the PTM_SHUTDOWN command to the SWTPM
 */
int main(int argc, char *argv[])
{
	int socket_fd, socket_flags, option_value;
	socklen_t option_length;
	unsigned long port_number;
	uint32_t message;
	ssize_t message_length;
	struct sockaddr_in serv_addr;

	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
	/* Parse arguments                                                            */
	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

	if(argc < 3)
	{
		printf("PTM_SHUTDOWN utility\n");
		printf("Usage:\n\tswtpm_shutdown <ip-of-swtpm> <port-of-swtpm>\n\n");
		return EXIT_FAILURE;
	}

	port_number = strtoul(argv[2], NULL, 0U);

	if ((port_number < 1U) || (port_number > 65535U))
	{
		fputs("Error: Could not parse the given port number!\n\n", stderr);
		return EXIT_FAILURE;
	}

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_number);

	if(inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0)
	{
		fputs("Error: Failed to parse the given IP address!\n\n", stderr);
		return EXIT_FAILURE;
	}

	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
	/* Create the socket                                                          */
	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

	printf("Shutting down the SWTPM at %s:%lu, please wait ...\n", argv[1], port_number);

	if((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fputs("Error: Could not create the TCP socket!\n\n", stderr);
		return EXIT_FAILURE;
	}

	socket_flags = fcntl(socket_fd, F_GETFL);

	if (socket_flags < 0)
	{
		fputs("Error: fcntl() has failed!\n\n", stderr);
		goto error_exit;
	}

	if (fcntl(socket_fd, F_SETFL, socket_flags | O_NONBLOCK) < 0)
	{
		fputs("Error: fcntl() has failed!\n\n", stderr);
		goto error_exit;
	}

	option_value = 1;

	if (setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (char*)&option_value, sizeof(option_value)) < 0)
	{
		fputs("Error: setsockopt() has failed!\n\n", stderr);
		goto error_exit;
	}

	option_value = sizeof(message);

	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVLOWAT, (char*)&option_value, sizeof(option_value)) < 0)
	{
		fputs("Error: setsockopt() has failed!\n\n", stderr);
		goto error_exit;
	}

	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
	/* Connect to SWTPM                                                           */
	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

	if(connect(socket_fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	{
		if (errno != EINPROGRESS)
		{
			PRINT_ERROR();
			fputs("Error: connect() has failed!\n%s\n\n", stderr);
			goto error_exit;
		}
	}

	if (await_socket(socket_fd, 1, TIMEOUT) <= 0)
	{
		fputs("Error: The connection timed out!\n\n", stderr);
		goto error_exit;
	}

	option_length = sizeof(option_value);

	if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &option_value, &option_length) < 0)
	{
		fputs("Error: Failed to get connection status!\n\n", stderr);
		goto error_exit;
	}

	if (option_length != sizeof(option_value))
	{
		fputs("Error: Failed to get connection status!\n\n", stderr);
		goto error_exit;
	}

	if (option_value != 0)
	{
		fprintf(stderr, "Error: Failed to connect! [SO_ERROR = %d]\n\n", option_value);
		goto error_exit;
	}

	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
	/* Send the command                                                           */
	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

	message = htobe32(ioctl_to_cmd(PTM_SHUTDOWN));

	if ((message_length = send(socket_fd, &message, sizeof(message), 0)) < 0)
	{
		PRINT_ERROR();
		fputs("Error: Failed to send the command!\n\n", stderr);
		goto error_exit;
	}

	if (message_length != sizeof(message))
	{
		fprintf(stderr, "Error: Command was not fully sent! [length = %u]\n\n", (unsigned)message_length);
		goto error_exit;
	}

	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
	/* Receive the response                                                       */
	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

	if (await_socket(socket_fd, 0, TIMEOUT) <= 0)
	{
		fputs("Error: The read operation timed out!\n\n", stderr);
		goto error_exit;
	}

	if ((message_length = recv(socket_fd, &message, sizeof(message), MSG_WAITALL)) < 0)
	{
		PRINT_ERROR();
		fputs("Error: Failed to read the response!\n\n", stderr);
		goto error_exit;
	}

	if (message_length != sizeof(message))
	{
		fprintf(stderr, "Error: Response code is incomplete! [length = %u]\n\n", (unsigned)message_length);
		goto error_exit;
	}

	message = be32toh(message);

	if (message != 0U)
	{
		fprintf(stderr, "Command failed with response code: 0x%08lX\n\n", (unsigned long)message);
		goto error_exit;
	}

	printf("PTM_SHUTDOWN sent successfully.\n\n");

	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */
	/* Final clean up                                                             */
	/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ */

	close(socket_fd);

	return EXIT_SUCCESS;

error_exit:

	close(socket_fd);

	return EXIT_FAILURE;
}

static int await_socket(const int socket_fd, const int write, const time_t timeout_sec)
{
	fd_set sock_set;
	struct timeval timeout;

	FD_ZERO(&sock_set);
	FD_SET(socket_fd, &sock_set);

	memset(&timeout, 0, sizeof(timeout));
	timeout.tv_sec = timeout_sec;

	return select(socket_fd + 1, write ? NULL : &sock_set, write ? &sock_set : NULL, NULL, &timeout);
}

static uint32_t ioctl_to_cmd(const uint32_t ioctlnum)
{
	return ((ioctlnum >> _IOC_NRSHIFT) & _IOC_NRMASK) + 1;
}
