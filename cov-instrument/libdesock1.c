/* This code is GPLed by Yan Shoshitaishvili.
   Now adapted to daemon fuzz. */

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
#include <stdio.h>
#include <poll.h>
#include <stdarg.h>


int preeny_debug_on = 0;
int preeny_info_on = 0;
int preeny_error_on = 1;


void preeny_debug(char *format, ...) {
	if (!preeny_debug_on) {
		return;
	}

	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);

	fflush(stdout);
}


void preeny_info(char *format, ...) {
	if (!preeny_info_on) {
		return;
	}

	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);

	fflush(stdout);
}


void preeny_error(char *format, ...) {
	if (!preeny_error_on) {
		return;
	}

	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);

	fflush(stdout);
}


__attribute__((constructor))
void preeny_logging_init() {

	preeny_debug_on = preeny_debug_on ||
					  (getenv("PREENY_DEBUG") &&
					   strcmp(getenv("PREENY_DEBUG"), "1") == 0);

	preeny_info_on = preeny_info_on ||
					 (getenv("PREENY_INFO") &&
					  strcmp(getenv("PREENY_INFO"), "1") == 0);

	preeny_error_on = preeny_error_on ||
					  (getenv("PREENY_ERROR") &&
					   strcmp(getenv("PREENY_ERROR"), "1") == 0);

}


#define PREENY_MAX_FD 8192
#define PREENY_SOCKET_OFFSET 500
#define READ_BUF_SIZE 65536

#define PREENY_SOCKET(x) (x + PREENY_SOCKET_OFFSET)


int preeny_desock_shutdown_flag = 0;
pthread_t *preeny_socket_threads_to_front[PREENY_MAX_FD] = { 0 };
pthread_t *preeny_socket_threads_to_back[PREENY_MAX_FD] = { 0 };


int should_intercept_sockfd(int sockfd) {
	if (sockfd >= 0 && sockfd < PREENY_MAX_FD) {
		return preeny_socket_threads_to_front[sockfd] != NULL;
	}
	return 0;
}


int preeny_socket_sync(int from, int to, int timeout) {

	struct pollfd poll_in = { from, POLLIN, 0 };
	char read_buf[READ_BUF_SIZE];
	int total_n;
	char error_buf[1024];
	int n;
	int r;

	r = poll(&poll_in, 1, timeout);
	if (r < 0) {
		strerror_r(errno, error_buf, 1024);
		preeny_debug("read poll() received error '%s' on fd %d\n", error_buf, from);
		return 0;
	}
	else if (poll_in.revents == 0) {
		// preeny_debug("read poll() timed out on fd %d\n", from);
		return 0;
	}

	total_n = read(from, read_buf, READ_BUF_SIZE);
	if (total_n < 0) {
		strerror_r(errno, error_buf, 1024);
		preeny_info("synchronization of fd %d to %d shutting down due to read error '%s'\n", from, to, error_buf);
		return -1;
	}
	else if (total_n == 0 && from == 0) {
		preeny_info("synchronization of fd %d to %d shutting down due to EOF\n", from, to);
		return -1;
	}
	preeny_debug("read %d bytes from %d (will write to %d)\n", total_n, from, to);

	n = 0;
	while (n != total_n) {
		r = write(to, read_buf, total_n - n);

		if (r < 0) {
			strerror_r(errno, error_buf, 1024);
			preeny_info("synchronization of fd %d to %d shutting down due to read error '%s'\n", from, to, error_buf);
			return -1;
		}

		n += r;
	}

	preeny_debug("wrote %d bytes to %d (had read from %d)\n", total_n, to, from);
	return total_n;
}


__attribute__((destructor))
void preeny_desock_shutdown() {

	int i;
	int to_sync[PREENY_MAX_FD] = { };

	preeny_debug("shutting down desock...\n");
	preeny_desock_shutdown_flag = 1;

	for (i = 0; i < PREENY_MAX_FD; i++) {
		if (preeny_socket_threads_to_front[i]) {
			preeny_debug("sending SIGINT to thread %d...\n", i);
			pthread_join(*preeny_socket_threads_to_front[i], NULL);
			pthread_join(*preeny_socket_threads_to_back[i], NULL);
			preeny_debug("... sent!\n");
			to_sync[i] = 1;
		}
	}

	for (i = 0; i < PREENY_MAX_FD; i++) {
		if (to_sync[i]) {
			while (preeny_socket_sync(PREENY_SOCKET(i), 1, 0) > 0);
		}
	}

	preeny_debug("... shutdown complete!\n");
}


void preeny_socket_sync_loop(int from, int to) {
	char error_buf[1024];
	int r;

	preeny_debug("starting forwarding from %d to %d!\n", from, to);

	while (!preeny_desock_shutdown_flag) {
		r = preeny_socket_sync(from, to, 15);
		if (r < 0) return;
	}
}


void *preeny_socket_sync_to_back(void *fd) {
	int front_fd = (int)fd;
	int back_fd = PREENY_SOCKET(front_fd);
	preeny_socket_sync_loop(back_fd, 1);
	return NULL;
}


void *preeny_socket_sync_to_front(void *fd) {
	int front_fd = (int)fd;
	int back_fd = PREENY_SOCKET(front_fd);
	preeny_socket_sync_loop(0, back_fd);
	return NULL;
}


int daemon_port = -1;
int daemon_accept_fd = -1;
int daemon_bind_fd = -1;


int (*original_socket)(int, int, int);
int (*original_bind)(int, const struct sockaddr *, socklen_t);
int (*original_listen)(int, int);
int (*original_accept)(int, struct sockaddr *, socklen_t *);
int (*original_accept4)(int, struct sockaddr *, socklen_t *, int);
int (*original_connect)(int, const struct sockaddr *, socklen_t);
int (*original_setsockopt)(int, int, int, const void *, socklen_t);
int (*original_close)(int);

int (*libc_recv)(int, void *, size_t, int);
int (*libc_send)(int, const void *, size_t, int);
int (*libc_read)(int, void *, size_t);
int (*libc_write)(int, const void *, size_t);
int (*libc_poll)(struct pollfd *, nfds_t, int);

__attribute__((constructor))
void preeny_desock_orig() {
	original_socket = dlsym(RTLD_NEXT, "socket");
	original_listen = dlsym(RTLD_NEXT, "listen");
	original_accept = dlsym(RTLD_NEXT, "accept");
	original_accept4 = dlsym(RTLD_NEXT, "accept4");
	original_bind = dlsym(RTLD_NEXT, "bind");
	original_connect = dlsym(RTLD_NEXT, "connect");
	original_close = dlsym(RTLD_NEXT, "close");
	original_setsockopt = dlsym(RTLD_NEXT, "setsockopt");

	libc_recv = dlsym(RTLD_NEXT, "recv");
	libc_send = dlsym(RTLD_NEXT, "send");
	libc_read = dlsym(RTLD_NEXT, "read");
	libc_write = dlsym(RTLD_NEXT, "write");
	libc_poll = dlsym(RTLD_NEXT, "poll");

	char *daemon_port_literal = (char *)getenv("AFL_DAEMON_LISTEN_PORT");
	if (!daemon_port_literal) {
		perror("preeny i need a port");
		fflush(stdout);
		_exit(0);
	}

	daemon_port = strtol(daemon_port_literal, NULL, 10);
}


int socket(int domain, int type, int protocol) {
	register long lr asm("lr");
	preeny_debug("socket callsite - %p\n", lr);

	int fds[2];
	int front_socket;
	int back_socket;

	if (domain != AF_INET && domain != AF_INET6) {
		preeny_info("Ignoring non-internet socket.");
		return original_socket(domain, type, protocol);
	}

	int r = socketpair(AF_UNIX, type, 0, fds);

	if (r != 0) {
		preeny_debug("socket errno! %d\n", errno);
		// perror("preeny socket emulation failed:");
		return original_socket(domain, type, protocol);
	}

	preeny_debug("Intercepted socket()!\n");

	preeny_debug("... created socket pair (%d, %d)\n", fds[0], fds[1]);

	front_socket = fds[0];
	back_socket = dup2(fds[1], PREENY_SOCKET(front_socket));
	close(fds[1]);

	preeny_debug("... dup into socketpair (%d, %d)\n", fds[0], back_socket);

	preeny_socket_threads_to_front[fds[0]] = malloc(sizeof(pthread_t));
	preeny_socket_threads_to_back[fds[0]] = malloc(sizeof(pthread_t));

	r = pthread_create(preeny_socket_threads_to_front[fds[0]], NULL, (void*(*)(void*))preeny_socket_sync_to_front, (void *)front_socket);
	if (r) {
		perror("failed creating front-sync thread");

		free(preeny_socket_threads_to_front[fds[0]]);
		free(preeny_socket_threads_to_back[fds[0]]);
		preeny_socket_threads_to_front[fds[0]] = NULL;
		preeny_socket_threads_to_back[fds[0]] = NULL;
		close(front_socket);
		close(back_socket);

		return -1;
	}

	r = pthread_create(preeny_socket_threads_to_back[fds[0]], NULL, (void*(*)(void*))preeny_socket_sync_to_back, (void *)front_socket);
	if (r) {
		perror("failed creating back-sync thread");

		free(preeny_socket_threads_to_front[fds[0]]);
		free(preeny_socket_threads_to_back[fds[0]]);
		preeny_socket_threads_to_front[fds[0]] = NULL;
		preeny_socket_threads_to_back[fds[0]] = NULL;
		close(front_socket);
		close(back_socket);

		return -1;
	}
	preeny_debug("--- socket %d\n", fds[0]);

	return fds[0];
}


unsigned long long time_milliseconds() {

	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * (unsigned long long)1000 + tv.tv_usec / 1000;

}

unsigned long long daemon_accept_last_hit = 0;

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	register long lr asm("lr");
	preeny_debug("--- accept %d %p\n", sockfd, lr);

	if (!should_intercept_sockfd(sockfd)) {
		return original_accept(sockfd, addr, addrlen);
	}

	unsigned long long current = time_milliseconds();
	if (current - daemon_accept_last_hit < 1000) {
		sleep(1);
	}
	daemon_accept_last_hit = time_milliseconds();

	//initialize a sockaddr_in for the peer
	struct sockaddr_in peer_addr;
	memset(&peer_addr, '0', sizeof(struct sockaddr_in));

	int accept_fd = dup(sockfd);

	if (daemon_accept_fd == -1 && daemon_bind_fd == sockfd) {
		daemon_accept_fd = accept_fd;
	}

	//Set the contents in the peer's sock_addr.
	//Make sure the contents will simulate a real client that connects with the intercepted server, as the server may depend on the contents to make further decisions.
	//The followings set-up should be fine with Nginx.
	peer_addr.sin_family = AF_INET;
	peer_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	peer_addr.sin_port = htons(9000);

	//copy the initialized peer_addr back to the original sockaddr. Note the space for the original sockaddr, namely addr, has already been allocated
	if (addr) {
		memcpy(addr, &peer_addr, sizeof(struct sockaddr_in));
	}

	return accept_fd;
}


int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {

	if (!should_intercept_sockfd(sockfd)) {
		return original_accept4(sockfd, addr, addrlen, flags);
	}

    return accept(sockfd, addr, addrlen);
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	preeny_debug("--- bind %d\n", sockfd);

	if (!should_intercept_sockfd(sockfd)) {
		return original_bind(sockfd, addr, addrlen);
	}

	if (daemon_port != -1 && daemon_bind_fd == -1) {
		if (daemon_port == ntohs(((struct sockaddr_in*)addr)->sin_port)) {
			daemon_bind_fd = sockfd;
		}
	}
	preeny_info("Emulating bind on port %d\n", ntohs(((struct sockaddr_in*)addr)->sin_port));
	return 0;
}


int listen(int sockfd, int backlog) {
	preeny_debug("--- listen %d\n", sockfd);

	if (!should_intercept_sockfd(sockfd)) {
		return original_listen(sockfd, backlog);
	}

	return 0;
}


int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	preeny_debug("--- connect %d\n", sockfd);

	if (!should_intercept_sockfd(sockfd)) {
		return original_connect(sockfd, addr, addrlen);
	}

	return 0;
}


int close(int sockfd) {
	preeny_debug("--- close %d\n", sockfd);

	if (!should_intercept_sockfd(sockfd)) {
		return original_close(sockfd);
	}

	// close one of the socket we intercepted, maybe exit here?
	preeny_debug("caught close %d %d\n", sockfd, daemon_accept_fd);
	if (sockfd == daemon_accept_fd) {
		_exit(0);
	}
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	int result = original_setsockopt(sockfd, level, optname, optval, optlen);
	preeny_debug("--- setsockopt %p %p %p %p %p %p %p\n", sockfd, level, optname, optval, optlen, result, errno);
	/* ignore errors */
	return 0;
}
int recv(int sockfd, void *buf, size_t length, int flags) {
	preeny_debug("--- recv %p %p %p %p\n", sockfd, buf, length, flags);

	int ret = libc_recv(sockfd, buf, length, flags);
	preeny_debug("--- recv %p %p\n", ret, errno);


	return ret;
}

int send(int sockfd, const void *buf, size_t length, int flags) {
	preeny_debug("--- send %p %p %p %p\n", sockfd, buf, length, flags);


	int ret = libc_send(sockfd, buf, length, flags);
	preeny_debug("--- send %p %p\n", ret, errno);


	return ret;
}

int read(int sockfd, void *buf, size_t length) {
	preeny_debug("--- read %p %p %p %p\n", sockfd, buf, length);


	int ret = libc_read(sockfd, buf, length);
	preeny_debug("--- read %p %p\n", ret, errno);


	return ret;
}

int write(int sockfd, const void *buf, size_t length) {
	preeny_debug("--- write %p %p %p %p\n", sockfd, buf, length);

	int ret = libc_write(sockfd, buf, length);
	preeny_debug("--- write %p %p\n", ret, errno);


	return ret;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
	preeny_debug("--- poll %p %p %p\n", fds, nfds, timeout);

	int ret = libc_poll(fds, nfds, timeout);
	preeny_debug("--- poll %p %p\n", ret, errno);


	return ret;
}
