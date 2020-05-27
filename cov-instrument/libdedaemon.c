/* hook for 2 possible daemonize process paths, fork()/setsid()/fork() and daemon() */

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

#define DEDAEMON_DEBUG_ENV "DEDAEMON_DEBUG"


/* global variables */

int dedaemon_in_debug = 0;
int dedaemon_after_fork = 0;


/* original libc function pointer */

int (*libc_fork)();
int (*libc_setsid)();
int (*libc_daemon)(int, int);


/* function declaration */

int afl_fork_okay();

void DEDAEMON_DEBUG(char * format, ...);

int fork();
int setsid();


/* conditionally debug output */

void DEDAEMON_DEBUG(char * format, ...) {

	if (!dedaemon_in_debug) {
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


/* setup libc function symbol, debug switch */

__attribute__((constructor)) void dedaemon_hook_init() {

	/* symbol lookup */

	libc_fork	= dlsym(RTLD_NEXT, "fork");
	libc_setsid	= dlsym(RTLD_NEXT, "setsid");
	libc_daemon	= dlsym(RTLD_NEXT, "daemon");

	/* debug switch */

	if (getenv(DEDAEMON_DEBUG_ENV)) {
		dedaemon_in_debug = 1;
	}
}


/* hook for fork */

int fork() {

	/* just forward if this is the fork call in the parent */

	if (!afl_fork_okay()) {
		return libc_fork();
	}

	DEDAEMON_DEBUG("--- fork()\n");

	/* otherwise, set the first_fork flag and pretend we are the child. */

	dedaemon_after_fork = 1;

	return 0;
}


/* hook for setsid */

int setsid() {

	/* just forward if there have not been a fork */

	if (!dedaemon_after_fork) {
		return libc_setsid();
	}

	DEDAEMON_DEBUG("--- setsid()\n");

	/* setsid() returns new session id, but we dont know any valid session id,
	   lets just forge one and hope it wont mess around. */

	return 0x12345;
}


/* hook for daemon */

int daemon(int nochdir, int noclose) {

	DEDAEMON_DEBUG("--- daemon(%p, %p)\n", nochdir, noclose);

	/* If nochdir is zero, daemon() changes the process's current working
	   directory to the root directory ("/"); */

	if (!nochdir) {
		chdir("/");
	}

	/* If noclose is zero, daemon() redirects standard input, standard
	   output and standard error to /dev/null; */

	if (!noclose) {

		int devnull = open("/dev/null", O_RDWR, 0);
		if (devnull == -1) {
			return -1;
		}
		dup2(devnull, STDIN_FILENO);
		dup2(devnull, STDOUT_FILENO);
		dup2(devnull, STDERR_FILENO);
		if (devnull > STDERR_FILENO) {
			close(devnull);
		}
	}

	/* pretend we are the child, and daemon succeed. */

	return 0;
}
