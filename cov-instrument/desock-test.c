#define _GNU_SOURCE

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <poll.h>
#include <stdarg.h>

void sender_server_handler(int daemon_port) {

	int ret = -1;

	/* set up listen socket for fuzzer */

	int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_sockaddr;
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port = htons(daemon_port);
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = bind(server_sockfd, (struct sockaddr *)&server_sockaddr,
		sizeof(server_sockaddr));
	if (ret == -1) {
		perror("bind");
		exit(1);
	}

	ret = listen(server_sockfd, 20);
	if (ret == -1) {
		perror("listen");
		exit(1);
	}

	struct sockaddr_in client_addr;
	socklen_t length = sizeof(client_addr);

	while (1) {

		/* new instance of afl-fuzz */

		int fuzzer_fd = accept(server_sockfd, (struct sockaddr*)&client_addr, &length);
		if (fuzzer_fd < 0) {
			perror("connect");
			continue;
		}

		char status[1024];

		ret = recv(fuzzer_fd, status, sizeof(status), 0);
		printf("1: %s\n", status);
		if (memcmp(status, "stage1", 6)) {
			perror("bad stage 1");
			close(fuzzer_fd);
			continue;
		}
		send(fuzzer_fd, "good stage 1\n", 12, 0);
		// sleep(1);
		printf("1-1: %s\n", status);

		ret = recv(fuzzer_fd, status, sizeof(status), 0);
		printf("2: %s\n", status);
		if (memcmp(status, "stage2", 6)) {
			perror("bad stage 2");
			close(fuzzer_fd);
			continue;
		}
		send(fuzzer_fd, "good stage 2\n", 12, 0);
		// sleep(1);
		printf("2-1: %s\n", status);

		ret = recv(fuzzer_fd, status, sizeof(status), 0);
		if (ret < 4) {
			send(fuzzer_fd, "nothing 1", 9, 0);
			close(fuzzer_fd);
			continue;
		}
		printf("3: %s", status);

		if ((*(unsigned char *)status) > 0x40) {
			send(fuzzer_fd, "nothing 2", 9, 0);
			close(fuzzer_fd);
			continue;
		}
		if ((*(unsigned char *)(status + 1)) > 0x40) {
			send(fuzzer_fd, "nothing 3", 9, 0);
			close(fuzzer_fd);
			continue;
		}
		if ((*(unsigned char *)(status + 2)) > 0x40) {
			send(fuzzer_fd, "nothing 4", 9, 0);
			close(fuzzer_fd);
			continue;
		}
		if ((*(unsigned char *)(status + 3)) > 0x40) {
			send(fuzzer_fd, "nothing 5", 9, 0);
			close(fuzzer_fd);
			continue;
		}

		send(fuzzer_fd, "crashed", 7, 0);
		printf("%s", (char *)0xdeadbeef);
	}

}

int main(int argc, char ** argv, char ** envp) {

	if (argc != 2) {
		printf("Usage: %s daemon_port\n", argv[0]);
		exit(1);
	}

	int daemon_port = strtol(argv[1], NULL, 10);
	if (!daemon_port) {
		printf("Invalid port number %s\n", argv[1]);
		exit(1);
	}

	printf("Target at %d\n", daemon_port);

	sender_server_handler(daemon_port);

	return 0;

}

