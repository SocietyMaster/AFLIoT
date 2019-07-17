/* This code is GPLed by Yan Shoshitaishvili.
   Now adapted to afl daemon fuzz. */

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


#define DESOCK_DEBUG_ENV "DESOCK_DEBUG"
#define DESOCK_PORT_ENV "DESOCK_PORT"


/* DESOCK_DEBUG logging utilities */

int in_debug = 0;


void DESOCK_DEBUG(char * format, ...) {

	if (!in_debug) {
		return;
	}

	va_list valist;
	va_start(valist, format);
	vprintf(format, valist);
	va_end(valist);

	fflush(stdout);

}


__attribute__((constructor))
void DEBUG_LOGGING_INIT() {

	if (getenv(DESOCK_DEBUG_ENV)) {
		in_debug = 1;
	}

}


/* file descriptor piping utilities */

#define BUFFER_SIZE 65536
#define DESOCK_MAX_FD 8192
#define DESOCK_FD(x) (x + 0x1000)


int desock_shutdown_flag = 0;
pthread_t *desock_thread_pipe_recv[DESOCK_MAX_FD] = { 0 };
pthread_t *desock_thread_pipe_send[DESOCK_MAX_FD] = { 0 };


int desock_socket_sync(int from, int to, int timeout) {

	struct pollfd poll_in = { from, POLLIN, 0 };
	char buffer[BUFFER_SIZE];
	int ret = 0;

	ret = poll(&poll_in, 1, timeout);
	if (ret < 0) {
		strerror_r(errno, buffer, sizeof(buffer));
		// DESOCK_DEBUG("read poll() on fd %d error: %s\n", from, buffer);
		return 0;
	}
	else if (poll_in.revents == 0) {
		// DESOCK_DEBUG("read poll() timed out on fd %d\n", from);
		return 0;
	}

	ret = read(from, buffer, BUFFER_SIZE);
	if (ret < 0) {
		strerror_r(errno, buffer, sizeof(buffer));
		// DESOCK_DEBUG("sync from fd %d to %d read error: %s\n", from, to, buffer);
		return -1;
	}
	else if (ret == 0 && from == 0) {
		// DESOCK_DEBUG("sync from fd %d to %d received EOF\n", from, to);
		return -1;
	}
	// DESOCK_DEBUG("sync from %d to %d read %d bytes\n", from, to, ret);

	int length = ret, length_done = 0;
	while (length_done != length) {
		ret = write(to, buffer, length - length_done);

		if (ret < 0) {
			strerror_r(errno, buffer, sizeof(buffer));
			// DESOCK_DEBUG("sync from fd %d to %d write error: %s\n", from, to, buffer);
			return -1;
		}

		length_done += ret;
	}

	// DESOCK_DEBUG("sync from %d to %d wrote %d bytes\n", to, from, length_done);
	return length_done;
}


__attribute__((destructor))
void desock_shutdown() {

	int to_sync[DESOCK_MAX_FD], i;
	memset(to_sync, 0, sizeof(to_sync));

	DESOCK_DEBUG("shutting down desock...\n");
	desock_shutdown_flag = 1;

	for (i = 0; i < DESOCK_MAX_FD; i++) {
		if (desock_thread_pipe_recv[i]) {
			DESOCK_DEBUG("sending SIGINT to thread %d...\n", i);
			pthread_join(*desock_thread_pipe_recv[i], NULL);
			pthread_join(*desock_thread_pipe_send[i], NULL);
			DESOCK_DEBUG("... sent!\n");
			to_sync[i] = 1;
		}
	}

	for (i = 0; i < DESOCK_MAX_FD; i++) {
		if (to_sync[i]) {
			while (desock_socket_sync(DESOCK_FD(i), 1, 0) > 0);
		}
	}

	DESOCK_DEBUG("... shutdown complete!\n");
}


void desock_socket_sync_loop(int from, int to) {

	DESOCK_DEBUG("starting forwarding from %d to %d!\n", from, to);

	while (!desock_shutdown_flag) {
		int ret = desock_socket_sync(from, to, 15);
		if (ret < 0) {
			return;
		}
	}
}


void *desock_socket_sync_send(void *fd) {

	/* from daemon to stdout */

	int desock_fd = DESOCK_FD((int)fd);
	desock_socket_sync_loop(desock_fd, 1);
	return NULL;
}


void *desock_socket_sync_recv(void *fd) {

	/* from stdin to daemon */

	int desock_fd = DESOCK_FD((int)fd);
	desock_socket_sync_loop(0, desock_fd);
	return NULL;
}


/* socket hook utilities */


#define DESOCK_MAX_SOCKOPT_ARGS 100


int desock_port = -1;
int desock_accept_fd = -1;
int desock_bind_fd = -1;
unsigned long long desock_accept_last_hit = 0;


typedef struct _SOCKET_ARGS {
	int domain;
	int type;
	int protocol;
	int valid;
} socket_args;


typedef struct _SOCKOPT_ARGS {
	int level;
	int optname;
	const void *optval;
	socklen_t optlen;
} sockopt_args;


typedef struct _PACK_SOCKOPT_ARGS {
	int counter;
	sockopt_args args[DESOCK_MAX_SOCKOPT_ARGS];
} pack_sockopt_args;


socket_args desock_socket_args[DESOCK_MAX_FD];
pack_sockopt_args desock_sockopt_args[DESOCK_MAX_FD];


enum DESOCK_OP {
	DESOCK_SOCKET,
	DESOCK_BIND,
	DESOCK_LISTEN,
	DESOCK_ACCEPT,
	DESOCK_ACCEPT4,
	DESOCK_SETSOCKOPT,
	DESOCK_CLOSE,
	DESOCK_EPOLL_CREATE,
	DESOCK_EPOLL_CREATE1,
	DESOCK_EPOLL_CTL,
	DESOCK_EPOLL_WAIT,
	DESOCK_EPOLL_PWAIT,
	DESOCK_SELECT,
	DESOCK_PSELECT,
	DESOCK_POLL,
	DESOCK_PPOLL
};


int (*libc_socket)(int, int, int);
int (*libc_bind)(int, const struct sockaddr *, socklen_t);
int (*libc_listen)(int, int);
int (*libc_accept)(int, struct sockaddr *, socklen_t *);
int (*libc_accept4)(int, struct sockaddr *, socklen_t *, int);
int (*libc_setsockopt)(int, int, int, const void *, socklen_t);
int (*libc_close)(int);

// int (*libc_recv)(int, void *, size_t, int);
// int (*libc_send)(int, const void *, size_t, int);
// int (*libc_read)(int, void *, size_t);
// int (*libc_write)(int, const void *, size_t);

int (*libc_epoll_create)(int);
int (*libc_epoll_create1)(int);
int (*libc_epoll_ctl)(int, int, int, struct epoll_event *);
int (*libc_epoll_wait)(int, struct epoll_event *, int, int);
int (*libc_epoll_pwait)(int, struct epoll_event *, int, int, const sigset_t *);
int (*libc_select)(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int (*libc_pselect)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *);
int (*libc_poll)(struct pollfd *, nfds_t, int);
int (*libc_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);


__attribute__((constructor))
void desock_hook_init() {
	libc_socket = dlsym(RTLD_NEXT, "socket");
	libc_bind = dlsym(RTLD_NEXT, "bind");
	libc_listen = dlsym(RTLD_NEXT, "listen");
	libc_accept = dlsym(RTLD_NEXT, "accept");
	libc_accept4 = dlsym(RTLD_NEXT, "accept4");
	libc_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
	libc_close = dlsym(RTLD_NEXT, "close");

	// libc_recv = dlsym(RTLD_NEXT, "recv");
	// libc_send = dlsym(RTLD_NEXT, "send");
	// libc_read = dlsym(RTLD_NEXT, "read");
	// libc_write = dlsym(RTLD_NEXT, "write");

	libc_epoll_create = dlsym(RTLD_NEXT, "epoll_create");
	libc_epoll_create1 = dlsym(RTLD_NEXT, "epoll_create1");
	libc_epoll_ctl = dlsym(RTLD_NEXT, "epoll_ctl");
	libc_epoll_wait = dlsym(RTLD_NEXT, "epoll_wait");
	libc_epoll_pwait = dlsym(RTLD_NEXT, "epoll_pwait");
	libc_select = dlsym(RTLD_NEXT, "select");
	libc_pselect = dlsym(RTLD_NEXT, "pselect");
	libc_poll = dlsym(RTLD_NEXT, "poll");
	libc_ppoll = dlsym(RTLD_NEXT, "ppoll");

	char *desock_port_literal = (char *)getenv(DESOCK_PORT_ENV);
	if (!desock_port_literal) {
		perror("desock init error: port needed");
		fflush(stdout);
		_exit(0);
	}

	desock_port = strtol(desock_port_literal, NULL, 10);
}

/*

unsigned long long time_milliseconds() {

	struct timeval tv;
	gettimeofday(&tv, NULL);

	return tv.tv_sec * (unsigned long long)1000 + tv.tv_usec / 1000;
}

*/

int desock_should_intercept(int sockfd, enum DESOCK_OP desock_op, int *args) {

	if (desock_op != DESOCK_CLOSE) {
		if (sockfd < 0 || sockfd >= DESOCK_MAX_FD) {
			return 0;
		}

		if (!desock_socket_args[sockfd].valid) {
			return 0;
		}
	}


	switch (desock_op) {

		case DESOCK_BIND: {
			return desock_port == args[0] && desock_bind_fd == -1;
		}

		case DESOCK_LISTEN: {
			return desock_bind_fd == sockfd;
		}

		case DESOCK_ACCEPT: {
			return desock_bind_fd == sockfd;
		}

		case DESOCK_ACCEPT4: {
			return desock_bind_fd == sockfd;
		}

		case DESOCK_SETSOCKOPT: {
			return 1;
		}

		case DESOCK_CLOSE: {
			return desock_accept_fd == sockfd;
		}
	}

	return 0;
}


int socket(int domain, int type, int protocol) {

	int sockfd = libc_socket(domain, type, protocol);

	DESOCK_DEBUG("--- socket(%p, %p, %p) = %p (%p)\n", domain, type, protocol,
		sockfd, errno);

	if (sockfd >= DESOCK_MAX_FD || sockfd < 0) {
		return sockfd;
	}

	socket_args *args = &desock_socket_args[sockfd];
	memset(args, 0, sizeof(socket_args));

	args->domain = domain;
	args->type = type;
	args->protocol = protocol;
	args->valid = 1;

	desock_sockopt_args[sockfd].counter = 0;

	return sockfd;
}


int setsockopt(int sockfd, int level, int optname, const void *optval,
			   socklen_t optlen) {

	int ret = libc_setsockopt(sockfd, level, optname, optval, optlen);

	DESOCK_DEBUG("--- setsockopt(%p, %p, %p, %p, %p) = %p (%p)\n", sockfd, level,
		optname, optval, optlen, ret, errno);

	if (!desock_should_intercept(sockfd, DESOCK_SETSOCKOPT, NULL)) {
		return ret;
	}

	pack_sockopt_args *pargs = &desock_sockopt_args[sockfd];
	sockopt_args *args = &pargs->args[pargs->counter];

	args->level = level;
	args->optname = optname;
	args->optval = optval;
	args->optlen = optlen;

	pargs->counter++;

	return ret;
}


int desock_socket_pipe(int sockfd) {

	socket_args *args = &desock_socket_args[sockfd];
	int domain = args->domain;
	int type = args->type;
	int protocol = args->protocol;

	if (domain != AF_INET && domain != AF_INET6) {
		return -1;
	}

	int fds[2], ret, i;

	/* only work under domain = AF_UNIX and protocol = 0 */

	ret = socketpair(AF_UNIX, type, 0, fds);
	if (ret != 0) {
		DESOCK_DEBUG("--- socketpair failed = %d (%d)\n", ret, errno);
		return -1;
	}

	DESOCK_DEBUG("--- socketpair() = (%d, %d)\n", fds[0], fds[1]);

	libc_close(sockfd);
	int front_socket = dup2(fds[0], sockfd);
	int back_socket = dup2(fds[1], DESOCK_FD(front_socket));
	libc_close(fds[1]);
	libc_close(fds[0]);

	DESOCK_DEBUG("--- dup2() = (%d, %d)\n", front_socket, back_socket);

	/* re-set the options on target sockfd again, ignore the errors */

	pack_sockopt_args *pargs = &desock_sockopt_args[sockfd];
	for (i = 0; i < pargs->counter; ++i) {
		sockopt_args *args = &pargs->args[i];
		ret = libc_setsockopt(sockfd, args->level, args->optname,
							  args->optval, args->optlen);
	}

	// pargs->counter = 0;

	desock_thread_pipe_recv[sockfd] = malloc(sizeof(pthread_t));
	desock_thread_pipe_send[sockfd] = malloc(sizeof(pthread_t));

	ret = pthread_create(desock_thread_pipe_recv[sockfd], NULL,
						 desock_socket_sync_recv, (void *)sockfd);
	if (ret) {
		perror("failed creating front-sync thread");

		free(desock_thread_pipe_recv[sockfd]);
		free(desock_thread_pipe_send[sockfd]);
		desock_thread_pipe_recv[sockfd] = NULL;
		desock_thread_pipe_send[sockfd] = NULL;
		libc_close(front_socket);
		libc_close(back_socket);

		return -1;
	}

	ret = pthread_create(desock_thread_pipe_send[sockfd], NULL,
						 desock_socket_sync_send, (void *)sockfd);
	if (ret) {
		perror("failed creating back-sync thread");

		free(desock_thread_pipe_recv[sockfd]);
		free(desock_thread_pipe_send[sockfd]);
		desock_thread_pipe_recv[sockfd] = NULL;
		desock_thread_pipe_send[sockfd] = NULL;
		libc_close(front_socket);
		libc_close(back_socket);

		return -1;
	}

	DESOCK_DEBUG("--- desock_socket_pipe() = %d\n", sockfd);
	return sockfd;
}


int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int bind_port = ntohs(((struct sockaddr_in*)addr)->sin_port);

	DESOCK_DEBUG("--- bind(%d, %d)\n", sockfd, bind_port);

	int args[1] = { bind_port };
	if (!desock_should_intercept(sockfd, DESOCK_BIND, args)) {
		return libc_bind(sockfd, addr, addrlen);
	}

	int ret = desock_socket_pipe(sockfd);
	if (ret == -1) {
		return libc_bind(sockfd, addr, addrlen);
	}
	desock_bind_fd = sockfd;

	DESOCK_DEBUG("--- bind(%d) succeed\n", bind_port);
	return 0;
}


int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	DESOCK_DEBUG("--- accept(%d)\n", sockfd);

	if (!desock_should_intercept(sockfd, DESOCK_ACCEPT, NULL)) {
		return libc_accept(sockfd, addr, addrlen);
	}

	/* only 1 instance of accept fd allowed */

	while (desock_accept_fd != -1) {
		sleep(1);
	}

	desock_accept_fd = dup(sockfd);

	DESOCK_DEBUG("--- accept_dup(%d) = %d\n", sockfd, desock_accept_fd);

	/* initialize a sockaddr_in for the peer */

	if (addr) {
		struct sockaddr_in *paddr = (struct sockaddr_in *)addr;
		memset(paddr, 0, sizeof(struct sockaddr_in));
		paddr->sin_family = AF_INET;
		paddr->sin_addr.s_addr = htonl(INADDR_ANY);
		paddr->sin_port = htons(9000);
	}

	return desock_accept_fd;
}


int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {

	DESOCK_DEBUG("--- accept4(%d)\n", sockfd);

	if (!desock_should_intercept(sockfd, DESOCK_ACCEPT4, NULL)) {
		return libc_accept4(sockfd, addr, addrlen, flags);
	}

    return accept(sockfd, addr, addrlen);
}


int listen(int sockfd, int backlog) {

	DESOCK_DEBUG("--- listen(%d)\n", sockfd);

	if (!desock_should_intercept(sockfd, DESOCK_LISTEN, NULL)) {
		return libc_listen(sockfd, backlog);
	}

	return 0;
}


int close(int sockfd) {

	if (!desock_should_intercept(sockfd, DESOCK_CLOSE, NULL)) {
		return libc_close(sockfd);
	}

	DESOCK_DEBUG("--- close(%d), accept_fd = %d\n", sockfd, desock_accept_fd);

	// close one of the socket we intercepted, exit here

	if (sockfd == desock_accept_fd) {
		desock_accept_fd = -1;

		_exit(0);
	}
}

#define DESOCK_MAX_EPOLL_EVENT 2000


typedef union _epoll_data {
	void        *ptr;
	int          fd;
	uint32_t     u32;
	uint64_t     u64;
} epoll_data_t;

typedef struct _epoll_event {
	uint32_t     events;      /* Epoll events */
	epoll_data_t data;        /* User data variable */
	int 		 eventfd;
} desock_epoll_event_t;

typedef struct _PACK_EPOLL_EVENT {
	int valid;
	int counter;
	desock_epoll_event_t events[DESOCK_MAX_EPOLL_EVENT];
} pack_epoll_event;


pack_epoll_event desock_epoll_events[DESOCK_MAX_FD];


int epoll_create(int size) {

	int epfd = libc_epoll_create(size);

	DESOCK_DEBUG("--- epoll_create(%p) = %p (%p)\n", size, epfd, errno);

	if (epfd < 0) {
		return epfd;
	}

	if (!desock_should_intercept(epfd, DESOCK_EPOLL_CREATE, NULL)) {
		return epfd;
	}

	desock_epoll_events[epfd].valid = 1;
	desock_epoll_events[epfd].counter = 0;
	return epfd;
}


int epoll_create1(int flags) {

	int epfd = libc_epoll_create1(flags);

	DESOCK_DEBUG("--- epoll_create1(%p) = %p (%p)\n", flags, epfd, errno);

	if (epfd < 0) {
		return epfd;
	}

	if (!desock_should_intercept(epfd, DESOCK_EPOLL_CREATE1, NULL)) {
		return epfd;
	}

	desock_epoll_events[epfd].valid = 1;
	desock_epoll_events[epfd].counter = 0;
	return epfd;
}


int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {

	int ret = libc_epoll_ctl(epfd, op, fd, event);

	DESOCK_DEBUG("--- epoll_ctl(%p, %p, %p) = %p (%p)\n", epfd, op, fd, ret, errno);

	if (ret < 0) {
		return ret;
	}

	if (!desock_should_intercept(epfd, DESOCK_EPOLL_CTL, NULL)) {
		return ret;
	}

	int curmax = desock_epoll_events[epfd].counter;

	if (op == EPOLL_CTL_ADD) {
		desock_epoll_events[epfd].counter++;
		epoll_event_t *devent = &desock_epoll_events[epfd].events[curmax];
		memcpy(devent, event, sizeof(struct epoll_event));
		devent->eventfd = fd;
	}
	else if (op == EPOLL_CTL_MOD) {
		for (int i = 0; i < curmax; ++i) {
			epoll_event_t *devent = &desock_epoll_events[epfd].events[i];
			if (devent->eventfd == fd) {
				memcpy(devent, event, sizeof(struct epoll_event));
				break;
			}
		}
	}
	else if (op == EPOLL_CTL_DEL) {
		int i = 0;
		for (; i < curmax; ++i) {
			epoll_event_t *devent = &desock_epoll_events[epfd].events[i];
			if (devent->eventfd == fd) {
				break;
			}
		}
		if (i != curmax) {
			memset(&desock_epoll_events[epfd].events[i], 0,
				sizeof(desock_epoll_event_t));
			memmove(&desock_epoll_events[epfd].events[i],
					&desock_epoll_events[epfd].events[i + 1],
					(curmax - i - 1) * sizeof(desock_epoll_event_t));
			desock_epoll_events[epfd].counter--;
		}
	}
}


int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {

	DESOCK_DEBUG("--- epoll_wait(%p, %p, %p, %p)\n", epfd, events, maxevents, timeout);

	if (maxevents <= 0) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	// we already accepted this
	if (desock_accept_fd != -1) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	int curmax = desock_epoll_events[epfd].counter;
	int i = 0;

	for (; i < curmax; ++i) {
		epoll_event_t *devent = &desock_epoll_events[epfd].events[i];
		if (devent->eventfd == desock_bind_fd) {
			break;
		}
	}

	if (i == curmax) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	int ret = 0;
	if (maxevents > 1) {
		ret = libc_epoll_wait(epfd, events + 1, maxevents - 1, 0);	// do not wait
		if (ret == -1) {
			return ret;
		}
	}

	// make a event for bind socket
	events[0].events = EPOLLIN;
	events[0].data.fd = desock_bind_fd;
	return ret + 1;
}


int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
	int timeout, const sigset_t *sigmask) {

	DESOCK_DEBUG("--- epoll_pwait(%p, %p, %p, %p, %p)\n", epfd, events, maxevents,
		timeout, sigmask);

	if (maxevents <= 0) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	// we already accepted this
	if (desock_accept_fd != -1) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	int curmax = desock_epoll_events[epfd].counter;
	int i = 0;

	for (; i < curmax; ++i) {
		epoll_event_t *devent = &desock_epoll_events[epfd].events[i];
		if (devent->eventfd == desock_bind_fd) {
			break;
		}
	}

	if (i == curmax) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	int ret = 0;
	if (maxevents > 1) {
		// do not wait
		ret = libc_epoll_pwait(epfd, events + 1, maxevents - 1, 0, sigmask);
		if (ret == -1) {
			return ret;
		}
	}

	// make a event for bind socket
	events[0].events = EPOLLIN;
	events[0].data.fd = desock_bind_fd;
	return ret + 1;
}


int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	struct timeval *timeout) {



}


int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	const struct timespec *timeout, const sigset_t *sigmask) {
}


int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
}


int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
	const sigset_t *sigmask) {

}



// int recv(int sockfd, void *buf, size_t length, int flags) {
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- recv %p %p %p %p\n", sockfd, buf, length, flags);
// 	}

// 	int ret = libc_recv(sockfd, buf, length, flags);
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- recv %p %p\n", ret, errno);
// 	}


// 	return ret;
// }

// int send(int sockfd, const void *buf, size_t length, int flags) {
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- send %p %p %p %p\n", sockfd, buf, length, flags);
// 	}


// 	int ret = libc_send(sockfd, buf, length, flags);
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- send %p %p\n", ret, errno);;
// 	}


// 	return ret;
// }

// int read(int sockfd, void *buf, size_t length) {
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- read %p %p %p %p\n", sockfd, buf, length);
// 	}


// 	int ret = libc_read(sockfd, buf, length);
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- read %p %p\n", ret, errno);
// 	}


// 	return ret;
// }

// int write(int sockfd, const void *buf, size_t length) {
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- write %p %p %p %p\n", sockfd, buf, length);
// 	}


// 	int ret = libc_write(sockfd, buf, length);
// 	if (desock_should_intercept(sockfd, DESOCK_OTHER, NULL)) {
// 	DESOCK_DEBUG("--- write %p %p\n", ret, errno);
// 	}


// 	return ret;
// }
