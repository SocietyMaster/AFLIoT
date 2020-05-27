/* gcc daemon-server.c -o daemon-server */


#include "libaflinit.h"


unsigned int in_debug = 0;
unsigned long long afl_forward_timeout = AFL_FORWARD_DEFAULT_TIMEOUT;


void DEBUG_PRINTF(char * format, ...) {

	if (!in_debug) {
		return;
	}

	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);

	fflush(stdout);

}


int recvn(int fd, void * buf, unsigned int length) {

	if (fd < 0) {
		return -1;
	}

	unsigned int loc = 0;
	while (loc < length) {
		int ret = recv(fd, (char *)buf + loc, length - loc, 0);
		if (ret <= 0) {
			break;
		}
		loc += ret;
	}

	return loc;
}


int sendn(int fd, void * buf, unsigned int length) {

	if (fd < 0) {
		return -1;
	}

	unsigned int loc = 0;
	while (loc < length) {
		int ret = send(fd, (char *)buf + loc, length - loc, 0);
		if (ret <= 0) {
			break;
		}
		loc += ret;
	}

	return loc;
}


unsigned long long time_milliseconds(void) {

	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * (unsigned long long)1000 + tv.tv_usec / 1000;

}


int check_timeout_then_wait(unsigned long long start) {

	unsigned long long stop = time_milliseconds();
	if (stop - start >= afl_forward_timeout) {
		return 1;
	}

	usleep(AFL_FORWARD_WAIT);

	return 0;
}


char file_buffer[BUFFER_SIZE];
char recv_buffer[BUFFER_SIZE];


/* sending file content to daemon listen address */

void forward_file_to_port(char *daemon_addr, int daemon_port, char *filepath) {

	unsigned long long start = time_milliseconds();
	int ret = -1;

	/* creating socket to connect daemon */

	int daemon_sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

	struct sockaddr_in daemon_sockaddr;
	memset(&daemon_sockaddr, 0, sizeof(daemon_sockaddr));

	daemon_sockaddr.sin_family = AF_INET;
	daemon_sockaddr.sin_port = htons(daemon_port);
	daemon_sockaddr.sin_addr.s_addr = inet_addr(daemon_addr);

	/* try connecting daemon until timeout reached, in case the daemon havent
	   finished initialization. */

	while (1) {

		ret = connect(daemon_sock, (struct sockaddr *)&daemon_sockaddr,
			sizeof(daemon_sockaddr));

		DEBUG_PRINTF("L%d connect %p %p\n", __LINE__, ret, errno);

		if (ret == 0) {
			break;
		}

		if (check_timeout_then_wait(start)) {
			puts("timeout connecting to daemon_server");
			close(daemon_sock);
			return;
		}

	}

	/* open input file */

	int input_fd = open(filepath, O_RDONLY);
	if (input_fd == -1) {
		puts("error opening the input file");
		close(daemon_sock);
		return;
	}

	/* read file content, send to daemon */

	while (1) {

		ret = read(input_fd, file_buffer, sizeof(file_buffer));

		DEBUG_PRINTF("L%d read %p %p\n", __LINE__, ret, errno);

		/* end of file reached or something else happened */

		if (ret <= 0) {
			break;
		}

		unsigned int length = ret;
		unsigned int loc = 0;

		while (loc < length) {

			ret = send(daemon_sock, file_buffer + loc, length - loc, 0);

			DEBUG_PRINTF("L%d send %p %p\n", __LINE__, ret, errno);

			if (ret > 0) {
				loc += ret;
				continue;
			}

			/* we cannot send more data to daemon, perhaps the buffer is full
			   and daemon stucks somewhere else. so we will try to receive
			   something, and maybe the daemon will move on.
			   ps: but i am not sure if ret == 0 do the same trick */

			if (ret == 0 || errno == EAGAIN || errno == EWOULDBLOCK) {

				ret = recv(daemon_sock, recv_buffer, sizeof(recv_buffer), 0);

				DEBUG_PRINTF("L%d recv %p %p\n", __LINE__, ret, errno);

				/* we have received something, so try again with send */

				if (ret > 0) {
					continue;
				}

				/* no luck with both recv and send, has daemon stucked?
				   we will keep trying until a timeout is reached anyway. */

				if (!check_timeout_then_wait(start)) {
					continue;
				}
			}

			/* looks like we are done here. */

			DEBUG_PRINTF("L%d timeout or bad socket\n", __LINE__);

			break;
		}

		/* only part of the file had been sent, but daemon is dead. */

		if (loc < length) {
			puts("error sending file to daemon");
			break;
		}
	}

	/* we will no longer write anything to the socket, lets shut it down
	   in case the daemon still want more and will back off.

	   FIXME: shutdown the socket result in heavily decrease of *path*
	   found by afl, maybe the short interval is not enough for daemon to
	   proceed, or it still want more on this socket. anyway, we will not
	   shut it down for now.
	   */

	ret = shutdown(daemon_sock, SHUT_WR);

	DEBUG_PRINTF("L%d shutdown %p %p\n", __LINE__, ret, errno);

	/* we have finished sending, but daemon may still rely on that socket to
	   to send us something, so lets wait for daemon to close the socket or a
	   timeout to come. */

	while (1) {

		ret = recv(daemon_sock, recv_buffer, sizeof(recv_buffer), 0);

		if (ret > 0) {
			continue;
		}

		/* this is an end of file */

		if (ret == 0) {
			break;
		}

		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			if (!check_timeout_then_wait(start)) {
				continue;
			}
		}

		break;
	}

	/* cleap up file descriptors */

	close(daemon_sock);
	close(input_fd);

}


/* handler for sender server */

void sender_server_handler(char *daemon_addr, int daemon_port) {

	char afl_file_path[PATH_MAX];
	int ret = -1;

	/* set up listen socket for fuzzer */

	int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in server_sockaddr;
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_port = htons(AFLNET_SENDER_PORT);
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

		/* receiving input file path afl-fuzz used */

		ret = recvn(fuzzer_fd, afl_file_path, sizeof(afl_file_path));
		if (ret != sizeof(afl_file_path)) {
			printf("error receiving afl_file_path\n");
			continue;
		}

		printf("fuzzer initiated with path %s\n", afl_file_path);

		while (1) {

			/* new instance of run case, hand-shake with target and get its pid */

			unsigned int status, ready = AFLNET_SENDER_ACK;
			unsigned int daemon_pid = -1;

			ret = recvn(fuzzer_fd, &status, sizeof(status));
			if (ret != sizeof(status) || status != AFLNET_SENDER_SYN) {
				printf("fuzzer may has exited.\n");
				break;
			}

			ret = recvn(fuzzer_fd, &daemon_pid, sizeof(daemon_pid));
			if (ret != sizeof(daemon_pid)) {
				printf("error receiving daemon's pid.\n");
				break;
			}

			ret = sendn(fuzzer_fd, &ready, sizeof(ready));
			if (ret != sizeof(ready)) {
				printf("error sending hand-shake ack\n");
				break;
			}

			unsigned long long start = time_milliseconds();

			/* target daemon is running, lets forward the input file */

			forward_file_to_port(daemon_addr, daemon_port, afl_file_path);

			unsigned long long stop = time_milliseconds();

			/* tell daemon we are done here, just quit

			   FIXME: this SIGUSR1 only caught by our handler in liaflinit.so several times
			   in a thousands executions, and all our sending operation returns succeed,
			   which is really wired. this result in multiple unknown crashes in afl, who
			   may recognized any signal as crash.
			   i have no idea why this happened? but we will send the signal for now, plus
			   a wait timeout. */

			// ret = kill(daemon_pid, SIGUSR1);

			DEBUG_PRINTF("kill SIGUSR1: %d %p %p\n", daemon_pid, ret, errno);

			DEBUG_PRINTF("done forwarding file - %lld\n", stop - start);

		}

		close(fuzzer_fd);

	}

}


int main(int argc, char ** argv, char ** envp) {

	if (argc != 3) {
		printf("Usage: %s daemon_addr daemon_port\n", argv[0]);
		exit(1);
	}

	char *daemon_addr = strdup(argv[1]);

	int daemon_port = strtol(argv[2], NULL, 10);
	if (!daemon_port) {
		printf("Invalid port number %s\n", argv[2]);
		exit(1);
	}

	printf("Target at %s:%d\n", daemon_addr, daemon_port);

	if (getenv(AFL_DAEMON_DEBUG_ENV)) {
		in_debug = 1;
	}

	char * forward_timeout_env = (char *)getenv(AFL_FORWARD_TIMEOUT_ENV);
	if (forward_timeout_env) {
		afl_forward_timeout = strtoull(forward_timeout_env, NULL, 10);
	}

	sender_server_handler(daemon_addr, daemon_port);

	return 0;

}
