/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include "libaflinit.h"

#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE];
u8* __afl_area_ptr = __afl_area_initial;

u8  __afl_detailed_cov_area_initial[MAP_SIZE];
u8* __afl_detailed_cov_area_ptr = __afl_detailed_cov_area_initial;

u32 __afl_shm_pointers[2];

u32 __afl_fork_okay = 0;


/* SHM setup. */

static void __afl_map_shm(void) {

    u8 *id_str = (u8 *)getenv(SHM_ENV_VAR);

    /* If we're running under AFL, attach to the appropriate region, replacing the
       early-stage __afl_area_initial region that is needed to allow some really
       hacky .init code to work correctly in projects such as OpenSSL. */

    if (id_str) {

        u32 shm_id = atoi((const char *)id_str);

        __afl_area_ptr = shmat(shm_id, NULL, 0);

        /* Whooooops. */

        if (__afl_area_ptr == (void *)-1) _exit(1);

        /* Write something into the bitmap so that even with low AFL_INST_RATIO,
           our parent doesn't give up on us. */

        __afl_area_ptr[0] = 1;

        /* Get detailed coverage map from parent */

        u8 *detailed_cov_id_str = (u8 *)getenv(SHM_DETAILED_COV_ENV_VAR);

        u32 detailed_cov_shm_id = atoi((const char *)detailed_cov_id_str);

        __afl_detailed_cov_area_ptr = shmat(detailed_cov_shm_id, NULL, 0);

        if (__afl_detailed_cov_area_ptr == (void *)-1) _exit(1);
    }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

    static u8 tmp[4];
    s32 child_pid;

    u8  child_stopped = 0;

    /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

    if (write(FORKSRV_FD + 1, tmp, 4) != 4) return;

    while (1) {

        u32 was_killed;
        int status;

        /* Wait for parent by reading from the pipe. Abort if read fails. */

        if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

        /* If we stopped the child in persistent mode, but there was a race
           condition and afl-fuzz already issued SIGKILL, write off the old
           process. */

        if (child_stopped && was_killed) {
            child_stopped = 0;
            if (waitpid(child_pid, &status, 0) < 0) _exit(1);
        }

        if (!child_stopped) {

            /* Once woken up, create a clone of our process. */

            child_pid = fork();
            if (child_pid < 0) _exit(1);

            /* In child process: close fds, resume execution. */

            if (!child_pid) {

                close(FORKSRV_FD);
                close(FORKSRV_FD + 1);
                return;

            }

        } else {

            /* Special handling for persistent mode: if the child is alive but
               currently stopped, simply restart it with SIGCONT. */

            kill(child_pid, SIGCONT);
            child_stopped = 0;

        }

        /* In parent process: write PID to pipe, then wait for child. */

        if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

        if (waitpid(child_pid, &status, 0) < 0)
            _exit(1);

        /* In persistent mode, the child stops itself with SIGSTOP to indicate
           a successful run. In this case, we want to wake it up without forking
           again. */

        if (WIFSTOPPED(status)) child_stopped = 1;

        /* Relay wait status to pipe, then loop back. */

        if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

    }

}


/* global file path */

char __afl_file_path[PATH_MAX];


/* socket with daemon-server */

int __afl_sender_sock = -1;


/* die printing message. */

void __afl_die(char * msg, int exit_code) {

    if (msg) {
        puts(msg);
    }

    _exit(exit_code);

}


/* send buffer content to daemon-server */

void __afl_sendn(void * buf, unsigned int length) {

    if (__afl_sender_sock == -1) {
        __afl_die("Uinitialized sender socket", 0);
    }

    unsigned int loc = 0;
    while (loc < length) {

        int ret = send(__afl_sender_sock, (char *)buf + loc, length - loc, 0);
        if (ret <= 0) {
            __afl_die("Error sending to sender", 0);
        }

        loc += ret;
    }

}


/* receive content from daemon-server */

void __afl_recvn(void * buf, unsigned int length) {

    if (__afl_sender_sock == -1) {
        __afl_die("Uinitialized sender socket", 0);
    }

    unsigned int loc = 0;
    while (loc < length) {

        int ret = recv(__afl_sender_sock, (char *)buf + loc, length - loc, 0);
        if (ret <= 0) {
            __afl_die("Error receving from sender", 0);
        }

        loc += ret;
    }

}


/* uclibc will not pass (argc, argv, envp) to .init_array entries, so
   we have no direct way to access argv array inside this init function,
   lets search for it manually. btw, fuck uclibc */

char ** __afl_find_argv() {

	/* envionrment candidates to search */

    char * env_cands[] = {"USER", "LD_LIBRARY_PATH", "HOME", "PATH", "PWD"};
    int env_cands_length = sizeof(env_cands) / sizeof(char *);

	/* find any possible environment on stack */

    char * env = NULL;
    int env_index = -1;

    while (++env_index < env_cands_length) {

        env = (char *)getenv(env_cands[env_index]);

        if (env) break;

    }

	/* nothing found */

    if (env_index == env_cands_length) {
        return NULL;
    }

	/* env is now pointing to the "value", what we need is the pointer of "key=value",
	   so subtract len("key=") to get the pointer. */

    env = env - strlen(env_cands[env_index]) - 1;

	/* env is now inside string storage area on stack, align it to pointer width,
	   and cast to char ** for further search */

    char ** pivot = (char **)(((unsigned long)env) & ~(sizeof(char *) - 1));

	/* search backward until some aligned pointer equals to env itself, which means
	   we have pivot == &envp[some_index], we will take it as inside_envp pointer */

    while (*--pivot != env);

    char * inside_envp = (char *)pivot;

	/* continue backward search until a NULL pointer is found, which means we have
	   pivot == &argv[last_index + 1], which is the end of argv array */

    while (*--pivot != NULL);

	/* all pointer inside argv points to string storage area, which is at the top
	   of the stack. and envp array is somewhere below this area, so anything below
	   envp array is definitely below string storage area, which is also definitely
	   not a pointer within argv array.
	   we can use this as a stop sign where argv ends, as for glibc and uclibc _start
	   stub it works well. however, for things that i havent test yet, this could
	   introduce some false positive, which will result in a few pointers that happens
	   to be higher than envp array but not actually one of argv. since what we do to
	   argv array is simple substitution of specified file path content, it is highly
	   unlikely that we might destory something else, totally acceptable.
	   now pivot is at the end of argv array, again we search backward until some
	   pointer is found that is smaller than or equal to inside_envp. */

    while (*--pivot > inside_envp);

	/* now we have argv == pivot + 1 */

    char ** argv = pivot + 1;

    return argv;
}


/* parse argument of program, find input file path and take it from here */

void __afl_parse_argument() {

    /* find argv array by searching the stack */

	char ** argv = __afl_find_argv();

	if (!argv) {
        __afl_die("Error looking for argv array", 1);
	}

    /* calculate argc from argv array */

	int argc = -1;
	while (argv[++argc]);

    /* find input file argument */

    int i = 0;
    char * prefix_head = NULL, * prefix_tail = NULL,
         * suffix_head = NULL, * suffix_tail = NULL;

    for (; i < argc; ++i) {

        prefix_head = strstr(argv[i], AFLFILE_PREFIX);
        if (!prefix_head)
            continue;

        prefix_tail = prefix_head + sizeof(AFLFILE_PREFIX) - 1;

        suffix_head = strstr(argv[i], AFLFILE_SUFFIX);
        if (!suffix_head)
            continue;

        suffix_tail = suffix_head + sizeof(AFLFILE_SUFFIX) - 1;

        break;

    }

    if (i == argc) {
        __afl_die("Error looking for input file path", 1);
    }

    /* setup file path */

    *suffix_head = '\0';
    realpath(prefix_tail, __afl_file_path);
    *suffix_head = AFLFILE_SUFFIX[0];

    /* fix original argument */

    unsigned int more_length = strlen(argv[i]) - (suffix_tail - argv[i]);
    memcpy(prefix_head, suffix_tail, more_length + 1);

    /* connect to sender */

    int sender_sock = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in sender_addr;
    memset(&sender_addr, 0, sizeof(sender_addr));

    sender_addr.sin_family = AF_INET;
    sender_addr.sin_port = htons(AFLNET_SENDER_PORT);
    sender_addr.sin_addr.s_addr = inet_addr(AFLNET_SENDER_ADDR);

    int ret = connect(sender_sock, (struct sockaddr *)&sender_addr, sizeof(sender_addr));
    if (ret < 0) {
        __afl_die("Error connecting to AFL-Net sender, start the server first", 1);
    }

    __afl_sender_sock = sender_sock;

    /* send __afl_file_path */

    __afl_sendn(__afl_file_path, sizeof(__afl_file_path));

}


/* timeout divide into seconds and microseconds */

unsigned int __afl_daemon_timeout_seconds = AFL_DAEMON_DEFAULT_TIMEOUT / 1000000;
unsigned int __afl_daemon_timeout_microseconds = AFL_DAEMON_DEFAULT_TIMEOUT % 1000000;


/* handler for microseconds alarm, just quit */

void __afl_daemon_timeout_microseconds_handler() {

    __afl_die(NULL, 0);

}


/* handler for seconds alarm */

void __afl_daemon_timeout_seconds_handler() {

	/* if microseconds == 0, then there is no need to setup another alarm,
	   just quit. */

	if (!__afl_daemon_timeout_microseconds) {
        __afl_die(NULL, 0);
    }

	/* otherwise setup a microseconds alarm, and set handler to the other one. */

	ualarm(__afl_daemon_timeout_microseconds, 0);

	signal(SIGALRM, __afl_daemon_timeout_microseconds_handler);

}


/* we do the heavy lift before the fork server initiated, setup
   the parameters for timeout */

void __afl_setup_timeout() {

    /* if the environment is set, use the timeout */

	char * timeout_env = (char *)getenv(AFL_DAEMON_TIMEOUT_ENV);

	if (timeout_env) {

		unsigned int __afl_daemon_timeout = strtoul(timeout_env, NULL, 10);

   	 	/* only set the timeout when it is not zero */

		if (__afl_daemon_timeout) {

			__afl_daemon_timeout_seconds = __afl_daemon_timeout / 1000000;
			__afl_daemon_timeout_microseconds = __afl_daemon_timeout % 1000000;

		}

	}

}


/* daemon may not commit suicide itself, lets do it here */

void __afl_enable_alarm() {

    /* if total timeout is less then 1 seconds, use the seconds handler to setup
       a microseconds alarm. */

	if (!__afl_daemon_timeout_seconds) {

		__afl_daemon_timeout_seconds_handler();

		return;
	}

    /* otherwise initiate a seconds alarm */

	alarm(__afl_daemon_timeout_seconds);

    /* send signal handler */

	signal(SIGALRM, __afl_daemon_timeout_seconds_handler);

}


/* fork-server had already been initiated, tell sender we are ready to go,
   and our pid as well, so it may tell when game is over. */

void __afl_notify_sender() {

    unsigned int ready = AFLNET_SENDER_SYN;
    __afl_sendn(&ready, sizeof(ready));

    unsigned int pid = getpid();
    __afl_sendn(&pid, sizeof(pid));

    unsigned int status;
    __afl_recvn(&status, sizeof(status));

    if (status != AFLNET_SENDER_ACK) {
        __afl_die("Handshake failed", 0);
    }

}


/* handler for SIGUSR1 send by daemon-server, which means we are done
   here, just quit. */

void __afl_sig_gameover_handler() {

    /* see if we caught the signal. */

    __afl_die(NULL, 0);

}


/* register the handler for sig_gameover */

void __afl_setup_sig_gameover() {

	signal(SIGUSR1, __afl_sig_gameover_handler);

}


/* This one can be called from user code when deferred forkserver mode
   is enabled. */

u32 * afl_manual_init() {

    static u8 init_done;

    if (!init_done) {

        __afl_map_shm();
        __afl_start_forkserver();

        init_done = 1;

        /* we will make no more fork call. */

        __afl_fork_okay = 1;
    }

    __afl_shm_pointers[0] = (u32)__afl_area_ptr;
    __afl_shm_pointers[1] = (u32)__afl_detailed_cov_area_ptr;

    return __afl_shm_pointers;
}


/* for extra daemon mode support, call this. */

u8 * afl_manual_init_daemon() {

    static u8 init_done;

    if (!init_done) {

        __afl_parse_argument();
        __afl_setup_timeout();

        __afl_map_shm();
        __afl_start_forkserver();

        __afl_setup_sig_gameover();
        __afl_enable_alarm();
        __afl_notify_sender();

        init_done = 1;

    }

    return __afl_area_ptr;

}


/* if we have passed fork stage, or failed */

u32 afl_fork_okay() {

    return __afl_fork_okay;

}
