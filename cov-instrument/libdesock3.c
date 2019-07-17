/* The original code is GPLed by Yan Shoshitaishvili. This one is almost
   rewritten to adapt to AFL daemonize fuzz, providing a much more robust
   socket hook mechanism for single port interception. */

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
#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stdarg.h>
#include <sys/syscall.h>


/* environments */

#define DESOCK_DEBUG_ENV "DESOCK_DEBUG"
#define DESOCK_PORT_ENV "DESOCK_PORT"
#define DESOCK_MULTI_ENV "DESOCK_MULTI"


/* DESOCK_DEBUG logging utilities */

int desock_in_debug = 0;


/* macros */

#define DESOCK_BUFFER_SIZE 0x10000
#define DESOCK_FD(x) (x + 0x1000)
#define DESOCK_MAX_FD 0x2000
#define DESOCK_MAX_EPOLL_EVENT 0x200
#define MAX(a,b) (((a)>(b))?(a):(b))


/* file descriptor piping utilities */

int desock_shutdown_flag = 0;
pthread_t desock_thread_pipe_recv;
pthread_t desock_thread_pipe_send;


/* socket hook utilities */

typedef struct socket_args {
	int domain;
	int type;
	int protocol;
	int valid;
} socket_args_t;

typedef struct desock_epoll_event {
	uint32_t	 events;
	epoll_data_t data;
	int 		 eventfd;
} desock_epoll_event_t;

typedef struct epoll_event_record {
	int valid;
	int counter;
	desock_epoll_event_t events[DESOCK_MAX_EPOLL_EVENT];
} epoll_event_record_t;

typedef struct epoll_register {
	struct epoll_event event;
	int epfd;
} epoll_register_t;

int desock_port = -1;
int desock_accept_fd = -1;
int desock_bind_fd = -1;
int desock_accept_multi = 0;

socket_args_t desock_socket_args[DESOCK_MAX_FD];
epoll_event_record_t desock_epoll_events[DESOCK_MAX_FD];


/* original libc function pointer */

int (*libc_socket)(int, int, int);
int (*libc_bind)(int, const struct sockaddr *, socklen_t);
int (*libc_listen)(int, int);
int (*libc_accept)(int, struct sockaddr *, socklen_t *);
int (*libc_accept4)(int, struct sockaddr *, socklen_t *, int);
int (*libc_setsockopt)(int, int, int, const void *, socklen_t);
int (*libc_close)(int);

int (*libc_fclose)(FILE *);
int (*libc_dup2)(int, int);

int (*libc_epoll_create)(int);
int (*libc_epoll_create1)(int);
int (*libc_epoll_ctl)(int, int, int, struct epoll_event *);
int (*libc_epoll_wait)(int, struct epoll_event *, int, int);
int (*libc_epoll_pwait)(int, struct epoll_event *, int, int,
	const sigset_t *);

int (*libc_select)(int, fd_set *, fd_set *, fd_set *,
	struct timeval *);
int (*libc_pselect)(int, fd_set *, fd_set *, fd_set *,
	const struct timespec *, const sigset_t *);
int (*libc_poll)(struct pollfd *, nfds_t, int);
int (*libc_ppoll)(struct pollfd *, nfds_t, const struct timespec *,
	const sigset_t *);


/* function declaration */

void DESOCK_DEBUG(char * format, ...);

int desock_socket_sync(int, int, int);
void desock_socket_sync_loop(int, int);
void *desock_socket_sync_thread(void *);

int desock_check_epfd(int);

int epoll_create(int);
int epoll_create1(int);
int epoll_ctl(int, int, int, struct epoll_event *);
int epoll_wait(int, struct epoll_event *, int, int);
int epoll_pwait(int, struct epoll_event *, int, int, const sigset_t *);

int desock_check_sockfd(int);

int socket(int, int, int);
int setsockopt(int, int, int, const void *, socklen_t);
int bind(int, const struct sockaddr *, socklen_t);
int accept(int, struct sockaddr *, socklen_t *);
int accept4(int, struct sockaddr *, socklen_t *, int);
int listen(int, int);
int close(int);

int fclose(FILE *);
int dup2(int, int);

int select(int, fd_set *, fd_set *, fd_set *, struct timeval *);
int pselect(int, fd_set *, fd_set *, fd_set *, const struct timespec *,
	const sigset_t *);
int poll(struct pollfd *, nfds_t, int);
int ppoll(struct pollfd *, nfds_t, const struct timespec *,
	const sigset_t *);

int desock_socket_pipe(int);


/******************************************************************************
 *
 * common utilities for the library
 *
 ******************************************************************************/


/* conditionally debug output */

void DESOCK_DEBUG(char * format, ...) {

	if (!desock_in_debug) {
		return;
	}
	pid_t tid = syscall(SYS_gettid);

	va_list valist;
	va_start(valist, format);
	printf("--- %p ", tid);
	vprintf(format, valist);
	va_end(valist);

	fflush(stdout);
}


/* setup libc function symbol, desock_port, debug switch and accept once */

__attribute__((constructor)) void desock_hook_init() {

	/* symbol lookup */

	void * handle = dlopen("libc.so.0", RTLD_LAZY);
	if (!handle) {
		handle = dlopen("libc.so.6", RTLD_LAZY);
		if (!handle) {
			puts("desock init: failed to open libc.so");
			exit(0);
		}
	}

	libc_socket			= dlsym(handle, "socket");
	libc_bind			= dlsym(handle, "bind");
	libc_listen			= dlsym(handle, "listen");
	libc_accept			= dlsym(handle, "accept");
	libc_accept4		= dlsym(handle, "accept4");
	libc_setsockopt		= dlsym(handle, "setsockopt");
	libc_close			= dlsym(handle, "close");
	libc_dup2			= dlsym(handle, "dup2");
	libc_fclose			= dlsym(handle, "fclose");
	libc_epoll_create	= dlsym(handle, "epoll_create");
	libc_epoll_create1	= dlsym(handle, "epoll_create1");
	libc_epoll_ctl		= dlsym(handle, "epoll_ctl");
	libc_epoll_wait		= dlsym(handle, "epoll_wait");
	libc_epoll_pwait	= dlsym(handle, "epoll_pwait");
	libc_select			= dlsym(handle, "select");
	libc_pselect		= dlsym(handle, "pselect");
	libc_poll			= dlsym(handle, "poll");
	libc_ppoll			= dlsym(handle, "ppoll");

	dlclose(handle);

	/* desock_port */

	char *desock_port_literal = (char *)getenv(DESOCK_PORT_ENV);
	if (!desock_port_literal) {
		perror("desock init error: port needed");
		fflush(stdout);
		_exit(0);
	}

	int ret = strtol(desock_port_literal, NULL, 10);
	if (!ret) {
		perror("desock init error: invalid port number");
		fflush(stdout);
		_exit(0);
	}
	desock_port = ret;

	/* debug switch */

	if (getenv(DESOCK_DEBUG_ENV)) {
		desock_in_debug = 1;
	}

	/* if we shall exit right after close on accept_sockfd */

	if (getenv(DESOCK_MULTI_ENV)) {
		desock_accept_multi = 1;
	}
}


/******************************************************************************
 *
 * basic socket function hook
 *
 ******************************************************************************/


/* check if sockfd is in range [0, DESOCK_MAX_FD], and if we recorded it */

int desock_check_sockfd(int sockfd) {

	if (sockfd < 0 || sockfd >= DESOCK_MAX_FD) {
		return 0;
	}

	return desock_socket_args[sockfd].valid == 1;
}


/* hook for socket, record all arguments if in range */

int socket(int domain, int type, int protocol) {

	int sockfd = libc_socket(domain, type, protocol);

	DESOCK_DEBUG("--- socket(%p, %p, %p) = %p (%p)\n", domain, type, protocol,
		sockfd, errno);

	if (sockfd >= DESOCK_MAX_FD || sockfd < 0) {
		return sockfd;
	}

	socket_args_t *args = &desock_socket_args[sockfd];
	memset(args, 0, sizeof(socket_args_t));

	args->domain = domain;
	args->type = type;
	args->protocol = protocol;
	args->valid = 1;

	return sockfd;
}


/* hook for setsockopt, there are 1 conditions we shall block this call,
   + if desock_accept_fd is not -1 and equals to sockfd, then this is the "accepted"
     fd we created with socketpair(), block the setsockopt
   for any other situation, let it pass */

int setsockopt(int sockfd, int level, int optname, const void *optval,
			   socklen_t optlen) {

	if (desock_accept_fd != -1 && desock_accept_fd == sockfd) {
		return 0;
	}

	int ret = libc_setsockopt(sockfd, level, optname, optval, optlen);

	DESOCK_DEBUG("--- setsockopt(%p, %p, %p, %p, %p) = %p (%p)\n", sockfd, level,
		optname, optval, optlen, ret, errno);

	return ret;
}


/* hook for bind, this is where we could possibly know if the sockfd is our
   target bind sockfd, try to intercept it if for sure */

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {

	int bind_port = ntohs(((struct sockaddr_in*)addr)->sin_port);

	DESOCK_DEBUG("--- bind(%d, %d)\n", sockfd, bind_port);

	/* if this is the target port and we have not bind yet, do continue */

	if (!desock_check_sockfd(sockfd) ||
		!(desock_port == bind_port && desock_bind_fd == -1)) {
		return libc_bind(sockfd, addr, addrlen);
	}

	/* record which sockfd is binded to target port */

	desock_bind_fd = sockfd;

	DESOCK_DEBUG("--- bind(%d) succeed\n", bind_port);
	return 0;
}


/* hook for accept, if sockfd is the bind_sockfd, we shall create socketpair
   here so it can be used into piping for futher io */

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {

	DESOCK_DEBUG("--- accept(%d)\n", sockfd);

	if (!desock_check_sockfd(sockfd) ||
		desock_bind_fd != sockfd) {
		return libc_accept(sockfd, addr, addrlen);
	}

	/* only one instance of accept fd allowed at the same time, may block here
	   forever or will continue when current accept fd is closed. if O_NONBLOCK
	   is set, return failed at once, otherwise wait for accept_fd to be ready. */

	if (desock_accept_fd != -1) {

		if (fcntl(sockfd, F_GETFL, NULL) & O_NONBLOCK) {

			DESOCK_DEBUG("--- accept(%d) failed O_NONBLOCK\n", sockfd);

			errno = EAGAIN;
			return -1;
		}

		DESOCK_DEBUG("--- accept(%d) will block\n", sockfd);

		while (desock_accept_fd != -1) {
			usleep(100);
		}
	}

	/* try do socketpair here */

	int ret = desock_socket_pipe(sockfd);
	if (ret == -1) {
		return libc_accept(sockfd, addr, addrlen);
	}
	desock_accept_fd = ret;

	DESOCK_DEBUG("--- accept_dup(%d) = %d\n", sockfd, desock_accept_fd);

	/* initialize a sockaddr_in for the peer */

	if (addr) {
		struct sockaddr_in *paddr = (struct sockaddr_in *)addr;
		memset(paddr, 0, sizeof(struct sockaddr_in));
		paddr->sin_family = AF_INET;
		paddr->sin_addr.s_addr = htonl(INADDR_ANY);
		paddr->sin_port = htons(0xdead);
	}

	return desock_accept_fd;
}


/* hook for accept4, if sockfd does not match, try original accept4, otherwise
   use accept instead. */

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {

	DESOCK_DEBUG("--- accept4(%d)\n", sockfd);

	if (!desock_check_sockfd(sockfd) ||
		desock_bind_fd != sockfd) {
		return libc_accept4(sockfd, addr, addrlen, flags);
	}

	return accept(sockfd, addr, addrlen);
}


/* hook for lisetn, if sockfd match, return success always. */

int listen(int sockfd, int backlog) {

	DESOCK_DEBUG("--- listen(%d)\n", sockfd);

	if (!desock_check_sockfd(sockfd) ||
		desock_bind_fd != sockfd) {
		return libc_listen(sockfd, backlog);
	}

	return 0;
}


/* hook for close, if sockfd match and accept once, just exit. */

int close(int sockfd) {

	DESOCK_DEBUG("--- close(%d), accept_fd = %d\n", sockfd, desock_accept_fd);

	if (sockfd == desock_accept_fd && desock_accept_fd != -1) {

		/* if we only accept once, then exit on close, otherwise set
		   desock_accept_fd back to -1, continue the loop */

		if (desock_accept_multi == 1) {
			int ret = libc_close(desock_accept_fd);
			desock_accept_fd = -1;
			return ret;
		}

		_exit(0);
	}

	/* we reply on stdin/stdout to perform desock, so block it */

	if (sockfd == 0 || sockfd == 1) {
		return 0;
	}

	if (!desock_check_sockfd(sockfd)) {
		return libc_close(sockfd);
	}

	desock_socket_args[sockfd].valid = 0;
	desock_epoll_events[sockfd].valid = 0;
	return libc_close(sockfd);
}


/******************************************************************************
 *
 * function hook for dup2/fclose, save stdio
 *
 ******************************************************************************/

/* hook for fclose, save stdin/stdout for desock. */

int fclose(FILE *stream) {

	DESOCK_DEBUG("--- fclose(%p), %p, %p\n", stream, stdin, stdout);

	if (stream == stdin || stream == stdout) {
		return 0;
	}

	return libc_fclose(stream);
}


/* hook for dup2, save stdin/stdout for desock. */

int dup2(int oldfd, int newfd) {

	DESOCK_DEBUG("--- dup2(%d, %d)\n", oldfd, newfd);

	/* we reply on stdin/stdout to perform desock, so block it */

	if (newfd == 0 || newfd == 1) {
		return newfd;
	}

	return libc_dup2(oldfd, newfd);
}


/******************************************************************************
 *
 * core function for creating socketpair and link target socket with stdio
 *
 ******************************************************************************/

int desock_socket_pipe(int sockfd) {

	/* extract the socket argument, and check for domain */

	socket_args_t *args = &desock_socket_args[sockfd];
	int domain = args->domain;
	int type = args->type;
	int protocol = args->protocol;

	if (domain != AF_INET && domain != AF_INET6) {
		DESOCK_DEBUG("--- desock_socket_pipe() bad domain = %d\n", domain);
		return -1;
	}

	/* create socketpair, only work under domain = AF_UNIX and protocol = 0 */

	int fds[2];
	int ret = socketpair(AF_UNIX, type, 0, fds);
	if (ret != 0) {
		DESOCK_DEBUG("--- socketpair() failed = %d (%d)\n", ret, errno);
		return -1;
	}

	DESOCK_DEBUG("--- socketpair() = (%d, %d)\n", fds[0], fds[1]);

	/* start piping thread here, the first pipes from stdin to desock_fd, malloced
	   parameter is necessary since the thread may start after this function ends,
	   any local variable may result in dangling pointer on stack. */

	int *param = (int *)malloc(sizeof(int) * 2);
	param[0] = 0;
	param[1] = DESOCK_FD(fds[0]);

	ret = pthread_create(&desock_thread_pipe_recv, NULL,
						 desock_socket_sync_thread, (void *)param);
	if (ret) {
		perror("failed creating front-sync thread");
		libc_close(fds[0]);
		libc_close(fds[1]);
		return -1;
	}

	/* the second pipes from desock_fd to stdout, we have to malloc again in case
	   the former thread have not extract the argument from previous heap in time. */

	param = (int *)malloc(sizeof(int) * 2);
	param[0] = DESOCK_FD(fds[0]);
	param[1] = 1;

	ret = pthread_create(&desock_thread_pipe_send, NULL,
						 desock_socket_sync_thread, (void *)param);
	if (ret) {
		perror("failed creating back-sync thread");
		libc_close(fds[0]);
		libc_close(fds[1]);
		return -1;
	}

	/* dup2 into desock_fd for another run if necessary. when we are here, accept_fd
	   is -1, which means we have already closed accept_fd on the application side,
	   there is no need for us to preserve any back_socket even when it is alive. */

	int front_socket = fds[0];
	int back_socket = DESOCK_FD(front_socket);
	/*
	while (1) {
		ret = fcntl(back_socket, F_GETFL, NULL);
		if (ret == -1 && errno == 9) {
			break;
		}
		usleep(10);
	}
	*/
	back_socket = dup2(fds[1], DESOCK_FD(front_socket));
	libc_close(fds[1]);

	/* socketpairs are ready, inform the piping threads to move on */

	DESOCK_DEBUG("--- desock_socket_pipe() = %d %d\n", front_socket, back_socket);
	return front_socket;
}


/******************************************************************************
 *
 * function hook for select/poll functions
 *
 ******************************************************************************/


/* hook for select */

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	struct timeval *timeout) {

	DESOCK_DEBUG("--- select(%p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds);

	if (!(desock_bind_fd != -1 && desock_bind_fd < nfds &&
		  readfds != NULL && FD_ISSET(desock_bind_fd, readfds))) {
		return libc_select(nfds, readfds, writefds, exceptfds, timeout);
	}

	FD_CLR(desock_bind_fd, readfds);

	if (desock_accept_fd != -1) {

		/* if timeout is not infinite, check the rest and return */

		if (timeout != NULL) {
			return libc_select(nfds, readfds, writefds, exceptfds, timeout);
		}

		/* otherwise make a loop and check either rest fd or the accept_fd
		   is available, with timeout 1 milliseconds. */

		while (desock_accept_fd != -1) {

			/* select may change timeout, reinitialize every time */

			struct timeval stimeout = {
				.tv_sec = 0,
				.tv_usec = 1000
			};

			int ret = libc_select(nfds, readfds, writefds, exceptfds, &stimeout);

			/* > 0 means some fds are ready, < 0 means error happened */

			if (ret != 0) {
				return ret;
			}
		}
	}

	struct timeval stimeout = {
		.tv_sec = 0,
		.tv_usec = 0
	};

	/* check the result with timeout == 0 */

	int ret = libc_select(nfds, readfds, writefds, exceptfds, &stimeout);
	int select_errno = errno;
	if (ret < 0) {
		return ret;
	}

	/* simulate read event for bind_fd */

	FD_SET(desock_bind_fd, readfds);
	errno = select_errno;
	return ret + 1;
}


/* hook for pselect */

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	const struct timespec *timeout, const sigset_t *sigmask) {

	DESOCK_DEBUG("--- pselect(%p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds);

	if (!(desock_bind_fd != -1 && desock_bind_fd < nfds &&
		  readfds != NULL && FD_ISSET(desock_bind_fd, readfds))) {
		return libc_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
	}

	FD_CLR(desock_bind_fd, readfds);

	if (desock_accept_fd != -1) {

		/* if timeout is not infinite, check the rest and return */

		if (timeout != NULL) {
			return libc_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
		}

		/* otherwise make a loop and check either rest fd or the accept_fd
		   is available, with timeout 1 milliseconds. */

		while (desock_accept_fd != -1) {

			/* select may change timeout, reinitialize every time */

			struct timespec stimeout = {
				.tv_sec = 0,
				.tv_nsec = 1 * 1000 * 1000
			};

			int ret = libc_pselect(nfds, readfds, writefds, exceptfds, &stimeout, sigmask);

			/* > 0 means some fds are ready, < 0 means error happened */

			if (ret != 0) {
				return ret;
			}
		}
	}

	struct timespec stimeout = {
		.tv_sec = 0,
		.tv_nsec = 0
	};

	/* check the result with timeout == 0 */

	int ret = libc_pselect(nfds, readfds, writefds, exceptfds, &stimeout, sigmask);
	int select_errno = errno;
	if (ret < 0) {
		return ret;
	}

	/* simulate read event for bind_fd */

	FD_SET(desock_bind_fd, readfds);
	errno = select_errno;
	return ret + 1;
}


/* hook for poll, same as epoll_wait, we have to manually enable bind_fd */

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {

	DESOCK_DEBUG("--- poll(%p, %p, %p)\n", fds, nfds, timeout);

	/* disable poll event for bind_fd */

	int poll_on_bind_fd = 0;

	for (int i = 0; i < nfds; ++i) {
		if (desock_bind_fd != -1 && fds[i].fd == desock_bind_fd) {
			fds[i].fd = -desock_bind_fd;
			poll_on_bind_fd = 1;
		}
	}

	/* if bind_fd is not present, just return to libc */

	if (!poll_on_bind_fd) {
		return libc_poll(fds, nfds, timeout);
	}

	/* if we have already accepted, check the rest */

	if (desock_accept_fd != -1) {

		/* if timeout is not infinite, check the rest and return */

		if (timeout >= 0) {
			int ret = libc_poll(fds, nfds, timeout);

			for (int i = 0; i < nfds; ++i) {
				if (desock_bind_fd != -1 && fds[i].fd == -desock_bind_fd) {
					fds[i].fd = desock_bind_fd;
					fds[i].revents = 0;
				}
			}

			return ret;
		}

		/* otherwise make a loop and check either rest fd or the accept_fd
		   is available, with timeout 1 milliseconds. */

		while (desock_accept_fd != -1) {

			int ret = libc_poll(fds, nfds, 1);

			/* > 0 means some fds are ready, < 0 means error happened */

			if (ret != 0) {
				for (int i = 0; i < nfds; ++i) {
					if (desock_bind_fd != -1 && fds[i].fd == -desock_bind_fd) {
						fds[i].fd = desock_bind_fd;
						fds[i].revents = 0;
					}
				}

				return ret;
			}
		}
	}

	/* we have disabled poll on bind_fd, just check others with timeout 0 */

	int ret = libc_poll(fds, nfds, 0);

	/* enable bind_fd, and manually set events to POLLIN */

	for (int i = 0; i < nfds; ++i) {
		if (desock_bind_fd != -1 && fds[i].fd == -desock_bind_fd) {
			fds[i].fd = desock_bind_fd;
			fds[i].revents = POLLIN;
			ret += 1;
		}
	}

	return ret;
}


/* hook for ppoll, mostly identical to poll */

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p,
	const sigset_t *sigmask) {

	DESOCK_DEBUG("--- ppoll(%p, %p, %p)\n", fds, nfds, tmo_p);

	/* disable poll event for bind_fd */

	int ppoll_on_bind_fd = 0;

	for (int i = 0; i < nfds; ++i) {
		if (desock_bind_fd != -1 && fds[i].fd == desock_bind_fd) {
			fds[i].fd = -desock_bind_fd;
			ppoll_on_bind_fd = 1;
		}
	}

	/* if bind_fd is not present, just return to libc */

	if (!ppoll_on_bind_fd) {
		return libc_ppoll(fds, nfds, tmo_p, sigmask);
	}

	/* if we have already accepted, check the rest */

	if (desock_accept_fd != -1) {

		/* if timeout is not infinite, check the rest and return */

		if (tmo_p != NULL) {
			int ret = libc_ppoll(fds, nfds, tmo_p, sigmask);

			for (int i = 0; i < nfds; ++i) {
				if (desock_bind_fd != -1 && fds[i].fd == -desock_bind_fd) {
					fds[i].fd = desock_bind_fd;
					fds[i].revents = 0;
				}
			}

			return ret;
		}

		/* otherwise make a loop and check either rest fd or the accept_fd
		   is available, with timeout 1 milliseconds. */

		struct timespec poll_timer = {
			.tv_sec = 0,
			.tv_nsec = 1 * 1000 * 1000
		};

		while (desock_accept_fd != -1) {

			int ret = libc_ppoll(fds, nfds, &poll_timer, sigmask);

			/* > 0 means some fds are ready, < 0 means error happened */

			if (ret != 0) {
				for (int i = 0; i < nfds; ++i) {
					if (desock_bind_fd != -1 && fds[i].fd == -desock_bind_fd) {
						fds[i].fd = desock_bind_fd;
						fds[i].revents = 0;
					}
				}

				return ret;
			}
		}
	}

	/* we have disabled poll on bind_fd, just check others with timeout 0 */

	struct timespec poll_timer = {
		.tv_sec = 0,
		.tv_nsec = 0
	};

	int ret = libc_ppoll(fds, nfds, &poll_timer, sigmask);

	/* enable bind_fd, and manually set events to POLLIN */

	for (int i = 0; i < nfds; ++i) {
		if (desock_bind_fd != -1 && fds[i].fd == -desock_bind_fd) {
			fds[i].fd = desock_bind_fd;
			fds[i].revents = POLLIN;
			ret += 1;
		}
	}

	return ret;
}


/******************************************************************************
 *
 * epoll instance hook utilities, since we close bind_sockfd somewhere else,
 * this creates a inconsistency between user-space file descriptor and kernel-space
 * file description, further epoll_wait on bind_sockfd will result in a faulty
 * event, so proper hook is needed.
 *
 ******************************************************************************/


/* check if epfd in range [0, DESOCK_MAX_FD] and if we have seen it */

int desock_check_epfd(int epfd) {

	if (epfd < 0 || epfd >= DESOCK_MAX_FD) {
		return 0;
	}

	return desock_epoll_events[epfd].valid == 1;
}


/* hook for epoll_create, record epfd if could */

int epoll_create(int size) {

	int ret = libc_epoll_create(size);

	DESOCK_DEBUG("--- epoll_create(%p) = %p (%p)\n", size, ret, errno);

	if (ret < 0) {
		return ret;
	}

	int epfd = ret;
	if (epfd < 0 || epfd >= DESOCK_MAX_FD) {
		return epfd;
	}

	desock_epoll_events[epfd].valid = 1;
	desock_epoll_events[epfd].counter = 0;
	return epfd;
}


/* almost identical to epoll_create */

int epoll_create1(int flags) {

	int ret = libc_epoll_create1(flags);

	DESOCK_DEBUG("--- epoll_create1(%p) = %p (%p)\n", flags, ret, errno);

	if (ret < 0) {
		return ret;
	}

	int epfd = ret;
	if (epfd < 0 || epfd >= DESOCK_MAX_FD) {
		return epfd;
	}

	desock_epoll_events[epfd].valid = 1;
	desock_epoll_events[epfd].counter = 0;
	return epfd;
}


/* hook for epoll_ctl, record every fd registered */

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {

	int ret = libc_epoll_ctl(epfd, op, fd, event);

	DESOCK_DEBUG("--- epoll_ctl(%p, %p, %p) = %p (%p)\n", epfd, op, fd, ret, errno);
	DESOCK_DEBUG("--- %p\n", event);
	if (event) {
		DESOCK_DEBUG("--- %p %p\n", event->events, event->data.u64);
	}

	if (ret < 0) {
		return ret;
	}

	if (!desock_check_epfd(epfd)) {
		return ret;
	}

	int curmax = desock_epoll_events[epfd].counter;

	if (op == EPOLL_CTL_ADD) {
		if (desock_epoll_events[epfd].counter == DESOCK_MAX_EPOLL_EVENT) {
			DESOCK_DEBUG("--- epoll_ctl(%p), too much event\n", epfd);
			_exit(0);
		}
		desock_epoll_events[epfd].counter++;
		desock_epoll_event_t *devent = &desock_epoll_events[epfd].events[curmax];
		memcpy(devent, event, sizeof(struct epoll_event));
		devent->eventfd = fd;
	}
	else if (op == EPOLL_CTL_MOD) {
		for (int i = 0; i < curmax; ++i) {
			desock_epoll_event_t *devent = &desock_epoll_events[epfd].events[i];
			if (devent->eventfd == fd) {
				memcpy(devent, event, sizeof(struct epoll_event));
				break;
			}
		}
	}
	else if (op == EPOLL_CTL_DEL) {
		int i = 0;
		for (; i < curmax; ++i) {
			desock_epoll_event_t *devent = &desock_epoll_events[epfd].events[i];
			if (devent->eventfd == fd) {
				break;
			}
		}
		if (i != curmax) {
			memmove(&desock_epoll_events[epfd].events[i],
					&desock_epoll_events[epfd].events[i + 1],
					(curmax - i - 1) * sizeof(desock_epoll_event_t));
			desock_epoll_events[epfd].counter--;
		}
	}

	return ret;
}


/* hook for epoll_wait, if we have not accept(bind_sockfd), and bind_sockfd is in
   the list of epoll events, then we can perform a manual epullin for bind_sockfd
   here, and also tries to get other events. */

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {

	DESOCK_DEBUG("--- epoll_wait(%p, %p, %p, %p)\n", epfd, events, maxevents, timeout);

	/* maxevents should be greater than 0, let libc set the errno */

	if (maxevents <= 0) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	/* if epfd is not invalid, just back off */

	if (!desock_check_epfd(epfd)) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	/* we have not even bind the target port yet */

	if (desock_bind_fd == -1) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	/* find bind_sockfd if it is in the event list */

	int curmax = desock_epoll_events[epfd].counter;
	int i = 0;
	desock_epoll_event_t *devent = NULL;
	for (; i < curmax; ++i) {
		devent = &desock_epoll_events[epfd].events[i];
		if (devent->eventfd == desock_bind_fd) {
			break;
		}
	}

	/* no bind_sockfd found, just let it go */

	if (i == curmax) {
		return libc_epoll_wait(epfd, events, maxevents, timeout);
	}

	/* we have bind the port, and the epfd contains the target bind_sockfd,
	   but we already accepted the socket, so wait for other events or when
	   accept_fd is free. */

	if (desock_accept_fd != -1) {

		/* note that dup(bind_sockfd) == accept_fd, so any write to the socketpair
		   will result EPOLLIN in both accept_epfd and bind_epfd, we certainly do not
		   want that, so remove bind_epfd first */

		libc_epoll_ctl(epfd, EPOLL_CTL_DEL, desock_bind_fd, NULL);

		/* it will finally return even if no event is available, so be it */

		if (timeout != -1) {
			int ret = libc_epoll_wait(epfd, events, maxevents, timeout);
			int wait_errno = errno;
			libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
				(struct epoll_event *)devent);
			errno = wait_errno;
			return ret;
		}

		/* this may block forever if we remove the bind_fd, so make a loop
		   to check if accept_fd is free or another event is delivered. */

		while (desock_accept_fd != -1) {

			/* check every 1 milliseconds */

			int ret = libc_epoll_wait(epfd, events, maxevents, 1);
			int wait_errno = errno;

			/* if anything goes wrong, or at least 1 event besides bind_fd is
			   available, send it back */

			if (ret != 0) {
				libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
					(struct epoll_event *)devent);
				errno = wait_errno;
				return ret;
			}
		}

		/* accept_fd is now free, lets restore the epoll event and continue */

		libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
			(struct epoll_event *)devent);
	}

	/* we are all good here, since socketpair will not create a EPOLLIN event
	   before we make input into it, so lets make it manually.

	   reserve the first slot of events buffer for bind_sockfd, then check for
	   other events to fill the rest of events buffer. timeout should be 0
	   so we will not stuck here, since we always have an "accept" event ready */

	int ret = 0;
	if (maxevents > 1) {

		/* remove bind_fd first to avoid accidental EPOLLIN event */

		libc_epoll_ctl(epfd, EPOLL_CTL_DEL, desock_bind_fd, NULL);

		ret = libc_epoll_wait(epfd, events + 1, maxevents - 1, 0);
		int wait_errno = errno;

		/* add the bind_fd back to event poll */

		libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
			(struct epoll_event *)devent);

		if (ret == -1) {
			errno = wait_errno;
			return ret;
		}
	}

	/* make an event for bind_sockfd like we have a connection coming in, using
	   the first slot, note that the `data` field should be exactly the same what
	   the program registerd, but not just fd. so copy it instead of fd only */

	events[0].events = EPOLLIN;
	events[0].data.u64 = devent->data.u64;
	return ret + 1;
}


/* almost identical to epoll_wait */

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents,
	int timeout, const sigset_t *sigmask) {

	DESOCK_DEBUG("--- epoll_pwait(%p, %p, %p, %p, %p)\n", epfd, events, maxevents,
		timeout, sigmask);

	if (maxevents <= 0) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	if (!desock_check_epfd(epfd)) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	if (desock_bind_fd == -1) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	int curmax = desock_epoll_events[epfd].counter;
	int i = 0;
	desock_epoll_event_t *devent = NULL;
	for (; i < curmax; ++i) {
		devent = &desock_epoll_events[epfd].events[i];
		if (devent->eventfd == desock_bind_fd) {
			break;
		}
	}

	if (i == curmax) {
		return libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
	}

	if (desock_accept_fd != -1) {

		libc_epoll_ctl(epfd, EPOLL_CTL_DEL, desock_bind_fd, NULL);

		if (timeout != -1) {
			int ret = libc_epoll_pwait(epfd, events, maxevents, timeout, sigmask);
			int wait_errno = errno;
			libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
				(struct epoll_event *)devent);
			errno = wait_errno;
			return ret;
		}

		while (desock_accept_fd != -1) {

			int ret = libc_epoll_pwait(epfd, events, maxevents, 1, sigmask);
			int wait_errno = errno;

			if (ret != 0) {
				libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
					(struct epoll_event *)devent);
				errno = wait_errno;
				return ret;
			}
		}

		libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
			(struct epoll_event *)devent);
	}

	int ret = 0;
	if (maxevents > 1) {

		libc_epoll_ctl(epfd, EPOLL_CTL_DEL, desock_bind_fd, NULL);

		ret = libc_epoll_pwait(epfd, events + 1, maxevents - 1, 0, sigmask);
		int wait_errno = errno;

		libc_epoll_ctl(epfd, EPOLL_CTL_ADD, desock_bind_fd,
			(struct epoll_event *)devent);

		if (ret == -1) {
			errno = wait_errno;
			return ret;
		}
	}

	events[0].events = EPOLLIN;
	events[0].data.u64 = devent->data.u64;
	return ret + 1;
}


/******************************************************************************
 *
 * piping utilities fot forwarding data between socket and stdio
 *
 ******************************************************************************/


/* piping data from `from` to `to` with timeout */

int desock_socket_sync(int from, int to, int timeout) {

	struct pollfd poll_in = { from, POLLIN, 0 };
	char buffer[DESOCK_BUFFER_SIZE];
	int ret = 0;

	ret = libc_poll(&poll_in, 1, timeout);
	if (ret < 0) {
		return 0;
	}
	else if (poll_in.revents == 0) {
		return 0;
	}

	ret = read(from, buffer, DESOCK_BUFFER_SIZE);
	if (ret < 0) {
		return -1;
	}
	else if (ret == 0 && from == 0) {
		return -1;
	}

	int length = ret, length_done = 0;
	while (length_done != length) {
		ret = write(to, buffer, length - length_done);

		if (ret < 0) {
			return -1;
		}

		length_done += ret;
	}

	return length_done;
}


/* shutdown all threads for piping */

__attribute__((destructor)) void desock_shutdown() {

	DESOCK_DEBUG("shutting down desock...\n");
	desock_shutdown_flag = 1;

	if (desock_accept_fd != -1) {
		DESOCK_DEBUG("sending SIGINT to pipe thread\n");
		pthread_join(desock_thread_pipe_recv, NULL);
		pthread_join(desock_thread_pipe_send, NULL);
		while (desock_socket_sync(DESOCK_FD(desock_accept_fd), 1, 0) > 0);
	}

	DESOCK_DEBUG("... shutdown complete!\n");
}


/* sync loop */

void desock_socket_sync_loop(int from, int to) {

	DESOCK_DEBUG("starting forwarding from %d to %d!\n", from, to);

	/* if shutting down or target accept sockfd is closed, end the loop */

	while (!desock_shutdown_flag && desock_accept_fd != -1) {

		if (desock_socket_sync(from, to, 15) < 0) {
			break;
		}

	}

	return;
}


/* forward between 2 pipe endpoints */

void *desock_socket_sync_thread(void *fd) {

	int from = *(int *)fd;
	int to = *((int *)fd + 1);

	free(fd);

	/* wait for socketpair to be ready */

	while (desock_accept_fd == -1) {
		usleep(100);
	}

	desock_socket_sync_loop(from, to);

	/* we have to close the desock_fd here to properly propagate the EOF on
	   the other end */

	int desock_fd = MAX(from, to);
	if (desock_fd > DESOCK_FD(0)) {
		DESOCK_DEBUG("--- sync close(%d)\n", desock_fd);

		/* shutdown instead of close, in case the client have not read all
		   the data, and EOF pops up */
		shutdown(desock_fd, SHUT_WR);
		/* libc_close(desock_fd); */
	}

	return NULL;
}
