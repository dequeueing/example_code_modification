#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/file.h>
// #include <signal.h>
#include "mc.h"

#define SHM_START    0xffffffc040000000
#define PROC_CNT     0xffff
#define PROC_SIGNAL  SIGUSR1
#define PROC_INERTIA 0x3ff

// daemon signals
#define OPCODE_TERMINATE         2048
#define OPCODE_SHUTDOWN          2049

// proxy syscall number


#define SYSCALL_READ  0
#define SYSCALL_WRITE  1
#define SYSCALL_OPEN  2
#define SYSCALL_CLOSE  3
#define SYSCALL_STAT  4
#define SYSCALL_FSTAT  5
#define SYSCALL_LSTAT  6
#define SYSCALL_POLL  7
#define SYSCALL_LSEEK  8
#define SYSCALL_MMAP  9
#define SYSCALL_MPROTECT  10
#define SYSCALL_MUNMAP  11
#define SYSCALL_BRK  12
#define SYSCALL_RT_SIGACTION  13
#define SYSCALL_RT_SIGPROCMASK  14
#define SYSCALL_RT_SIGRETRUN  15
#define SYSCALL_IOCTL  16
#define SYSCALL_PREAD  17
#define SYSCALL_PWRITE  18
#define SYSCALL_WRITEV  20
#define SYSCALL_ACCESS  21
#define SYSCALL_PIPE  22
#define SYSCALL_SELECT  23
#define SYSCALL_SCHED_YIELD  24
#define SYSCALL_MADVISE  28
#define SYSCALL_DUP  32
#define SYSCALL_DUP2  33
#define SYSCALL_PAUSE  34
#define SYSCALL_GETPID  39
#define SYSCALL_SOCKET  41
#define SYSCALL_CONNECT  42
#define SYSCALL_ACCEPT  43
#define SYSCALL_SEND  44
#define SYSCALL_RECV 45
#define SYSCALL_SHUTDOWN  48
#define SYSCALL_BIND  49
#define SYSCALL_LISTEN  50
#define SYSCALL_GETSOCKNAME  51
#define SYSCALL_GETPEERNAME  52
#define SYSCALL_SOCKETPAIR  53
#define SYSCALL_SETSOCKOPT  54
#define SYSCALL_GETSOCKOPT  55
#define SYSCALL_CLONE  56
#define SYSCALL_FORK  57
#define SYSCALL_EXECVE  59
#define SYSCALL_EXIT  60
#define SYSCALL_WAIT4  61
#define SYSCALL_KILL  62
#define SYSCALL_UNAME  63
#define SYS_SEMGET     64
#define SYSCALL_FCNTL  72
#define SYSCALL_FSYNC  74
#define SYSCALL_FTRUNCATE  77
#define SYSCALL_GETCWD 79
#define SYSCALL_CHDIR  80
#define SYSCALL_FCHDIR 81
#define SYSCALL_RENAME 82
#define SYSCALL_MKDIR  83
#define SYSCALL_RMDIR  84
#define SYSCALL_LINK  86
#define SYSCALL_UNLINK  87
#define SYSCALL_SYMLINK  88
#define SYSCALL_READLINK  89
#define SYSCALL_CHMOD  90
#define SYSCALL_FCHMOD  91
#define SYSCALL_FCHOWN 93
#define SYSCALL_UMASK  95
#define SYSCALL_GETTIMEOFDAY  96
#define SYSCALL_GETUID  102
#define SYSCALL_GETGID  104
#define SYSCALL_SETUID  105
#define SYSCALL_SETGID  106
#define SYSCALL_GETEUID  107
#define SYSCALL_GETEGID  108
#define SYSCALL_SETPGID  109
#define SYSCALL_GETPPID  110
#define SYSCALL_GETPGRP  111
#define SYSCALL_SETSID  112
#define SYSCALL_SETREUID  113
#define SYSCALL_SETREGID  114
#define SYSCALL_GETGROUPS  115
#define SYSCALL_SETGROUPS  116
#define SYSCALL_SETRESUID  117
#define SYSCALL_GETRESUID  118
#define SYSCALL_SETRESGID  119
#define SYSCALL_GETRESGID  120
#define SYSCALL_SETFSUID  122
#define SYSCALL_SETFSGID  123
#define SYSCALL_GETSID  124
#define SYSCALL_SIGALTSTACK  131
#define SYSCALL_STATFS  137
#define SYSCALL_FSTATFS  138
#define SYSCALL_PRCTL  157
#define SYSCALL_ARCH_PRCTL  158
#define SYSCALL_SYNC  162
#define SYS_REBOOT 169 
#define SYSCALL_GETTID  186
#define SYSCALL_TIME  201
#define SYSCALL_FUTEX  202
#define SYSCALL_EPOLL_CREATE  213
#define SYSCALL_GETDENTS  217
#define SYSCALL_SET_TID_ADDRESS  218
#define SYSCALL_FADVISE 221
#define SYSCALL_CLOCK_GETTIME  228
#define SYSCALL_CLOCK_NANOSLEEP  230
#define SYSCALL_EXIT_GROUP  231
#define SYSCALL_EPOLL_WAIT  232
#define SYSCALL_EPOLL_CTL  233
#define SYSCALL_TGKILL  234
#define SYSCALL_WAITID  247
#define SYSCALL_OPENAT  257
#define SYSCALL_MKDIRAT  258
#define SYSCALL_FSTATAT  262
#define SYSCALL_UNLINKAT  263
#define SYSCALL_RENAMEAT  264
#define SYSCALL_LINKAT  265
#define SYSCALL_SYMLINKAT  266
#define SYSCALL_READLINKAT  267
#define SYSCALL_FCHMODAT  268
#define SYSCALL_FACCESSAT 269
#define SYSCALL_SET_ROBUST_LIST  273
#define SYSCALL_UTIMENSAT  280
#define SYSCALL_EPOLL_CREATE1  291
#define SYSCALL_DUP3 292
#define SYSCALL_PIPE2  293
#define SYSCALL_PRLIMIT64  302
#define SYSCALL_GETRANDOM  318
#define SYSCALL_EXECVEAT  322


#define log_ret(name) log(SYS, "'" name "' resulted in %lu", mc->ret)

static pid_t proc_map[PROC_CNT] = {0};

/**
 Handles the messages that contain proxy system calls.
 */
uint64_t
handle_syscall(mc_t *mc) {
    opcode_t opcode = mc->opcode;

    if (opcode == 0xffff) return 0;

    mc->ret = 0;

    switch (opcode) {
        case SYSCALL_OPENAT:
            //printf("pathname %s",(char *) mc->payload[0]);
            mc->ret = openat(mc->args[0] /* dirfd */,
                             (char *) mc->payload[0] /* filename */,
                             mc->args[1] /* flag */,
                             mc->args[2] /* mode */);
            log_ret("openat");
            break;
        case SYSCALL_GETDENTS:
//            mc->ret = getdents64(mc->args[0] /* fd */,
//                                 mc->payload[0] /* dirp */,
//                                 mc->args[1] /* count */);
            log_ret("getdents64");
            break;
        case SYSCALL_FACCESSAT:
            mc->ret = faccessat(mc->args[0] /* dirfd */,
                                (char *) mc->payload[0] /* filename */,
                                mc->args[1] /* mode */,
                                mc->args[2] /* flags */);
            log_ret("faccessat");
            break;
        case SYSCALL_CLOSE:
            mc->ret = close(mc->args[0]);
            log_ret("close");
            break;
        case SYSCALL_DUP:
            mc->ret = dup(mc->args[0]);
            log_ret("dup");
            break;
        case SYSCALL_DUP3:
            mc->ret = dup3(mc->args[0] /* oldfd */,
                           mc->args[1] /* newfd */,
                           mc->args[2] /* flags */);
            log_ret("dup3");
            break;
        case SYSCALL_GETCWD: {
            char *addr = getcwd((char *) mc->payload[0], /* buf */
                                mc->args[1] /* size */);
            mc->ret = strlen(addr);
            log_ret("getcwd");
            break;
        }
        case SYSCALL_FTRUNCATE:
            mc->ret = ftruncate(mc->args[0] /* fd */,
                                mc->args[1] /* length */);
            log_ret("ftruncate");
            break;
        case SYSCALL_LSEEK:
            mc->ret = lseek(mc->args[0] /* fd */,
                            mc->args[1] /* offset */,
                            mc->args[2] /* whence */);
            log_ret("lseek");
            break;
        case SYSCALL_LINKAT:
            mc->ret = linkat(mc->args[0] /* fd1 */,
                             (char *) mc->payload[0] /* old_path */,
                             mc->args[1] /* fd2 */,
                             (char *) mc->payload[1] /* new_path */,
                             mc->args[2] /* flag */);
            log_ret("linkat");
            break;
        case SYSCALL_UNLINKAT:
            mc->ret = unlinkat(mc->args[0] /* dirfd */,
                               (char *) mc->payload[0] /* path */,
                               mc->args[1] /* flag */);
            log_ret("unlinkat");
            break;
        case SYSCALL_FCNTL:
            mc->ret = fcntl(mc->args[0] /* fd */,
                            mc->args[1] /* cmd */,
                            mc->args[2] /* arg */);
            log_ret("fcntl");
            break;
        case SYSCALL_MKDIRAT:
            mc->ret = mkdirat(mc->args[0] /* dirfd */,
                              (char *) mc->payload[0] /* path */,
                              mc->args[1] /* mode */);
            log_ret("mkdirat");
            break;
        case SYSCALL_RMDIR:
            mc->ret = rmdir((char *) mc->payload[0] /* path */);
            log_ret("rmdir");
            break;
        case SYSCALL_CHDIR:
            mc->ret = chdir((char *) mc->payload[0] /* path */);
            log_ret("chdir");
            break;
        case SYSCALL_FCHDIR:
            mc->ret = fchdir(mc->args[0] /* fd */);
            log_ret("fchdir");
            break;
        case SYSCALL_CHMOD:
            mc->ret = chmod((char *) mc->payload[0] /* path */,
                            mc->args[0] /* mode */);
            log_ret("chmod");
            break;
        case SYSCALL_READ:
            //printf("%d %d\n",mc->args[0], mc->args[1]);
            mc->ret = read(mc->args[0] /* fd */,
                           mc->payload[0] /* buf */,
                           mc->args[1] /* len */);
            log_ret("read");
            break;
        case SYSCALL_PREAD:
            mc->ret = pread(mc->args[0] /* fd */,
                            mc->payload[0] /* buf */,
                            mc->args[1] /* len */,
                            mc->args[2] /* offset */);
            log_ret("pread");
            break;
        case SYSCALL_WRITE:
            mc->ret = write(mc->args[0] /* fd */,
                            mc->payload[0] /* buf */,
                            mc->args[1] /* len */);
            log_ret("write");
            break;
        case SYSCALL_PWRITE:
            mc->ret = pwrite(mc->args[0] /* fd */,
                             mc->payload[0] /* buf */,
                             mc->args[1] /* len */,
                             mc->args[2] /* offset */);
            log_ret("pwrite");
            break;
        case SYSCALL_READLINKAT:
            mc->ret = readlinkat(mc->args[0] /* dirfd */,
                                 (char *) mc->payload[0] /* path */,
                                 (char *) mc->payload[1] /* buf */,
                                 mc->args[1] /* bufsiz */);

            log_ret("readlinkat");
            break;
        case SYSCALL_FSTATAT:
            mc->ret = fstatat(mc->args[0] /* dirfd */,
                              (char *) mc->payload[0] /* path */,
                              (struct stat *) mc->payload[1] /* statbuf */,
                              mc->args[1] /* flag */);
            log_ret("fstatat");
            break;
        case SYSCALL_FSTAT:
            mc->ret = fstat(mc->args[0] /* fd */,
                            (struct stat *) mc->payload[0] /* statbuf */);
            log_ret("fstat");
            break;
//        case 160:  // uname
        case SYSCALL_GETRANDOM:
            mc->ret = getrandom(mc->payload[0] /* buf */,
                                mc->args[0] /* count */,
                                mc->args[1] /* flags */);
            log_ret("getrandom");
            break;
        case SYSCALL_SOCKET:
            mc->ret = socket(AF_INET /* domain */, SOCK_STREAM /* type */, 0 /* protocol */);
            log_ret("socket");
            break;
        case SYSCALL_CONNECT: {
            log(SYS, "begin to connect socket");

            int  fd   = mc->args[0];
            int  len  = mc->args[2];
            char *str = (char *) mc->payload[0];

            struct sockaddr_in sock_static;
            bzero((char *) &sock_static, sizeof(sock_static));
            sock_static.sin_family = AF_INET;
            sock_static.sin_port   = htons(mc->args[1] /* port */);

            char     str_real[len + 1];
            for (int i    = 0; i < len; i++) {
                str_real[i] = str[i];
            }
            str_real[len] = '\0';

            log(SYS, "connecting to addr: %s", str_real);

            sock_static.sin_addr.s_addr = inet_addr(str_real);

            log(SYS, "destination is %s", str_real);

            mc->ret = connect(fd,
                              (struct sockaddr *) &sock_static,
                              sizeof(sock_static));
            int cwnd = 2000;
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char *) &cwnd, sizeof(int));

            log(SYS, "end to connect socket, mc->return %ld", mc->ret);
            break;
        }
        case SYSCALL_BIND: {
            log(SYS, "begin to bind socket");

            int  len  = mc->args[2];
            char *str = (char *) mc->payload[0];

            struct sockaddr_in sock_static;
            bzero((char *) &sock_static, sizeof(sock_static));
            sock_static.sin_family = AF_INET;
            sock_static.sin_port   = htons(mc->args[1] /* port */);

            char     str_real[len + 1];
            for (int i    = 0; i < len; i++) {
                str_real[i] = str[i];
            }
            str_real[len] = '\0';

            log(SYS, "binding to addr: %s", str_real);

            sock_static.sin_addr.s_addr = inet_addr(str_real);
            mc->ret                     = bind(mc->args[0] /* fd */,
                                               (struct sockaddr *) &sock_static,
                                               sizeof(sock_static));

            log(SYS, "bind socket done");
            break;
        }
        case SYSCALL_LISTEN:
            mc->ret = listen(mc->args[0] /* fd */,
                             mc->args[1] /* num */);
            log_ret("listen");
            break;
        case SYSCALL_ACCEPT: {
            log(SYS, "begin to accept socket");

            struct sockaddr_in sock_client;
            bzero((char *) &sock_client, sizeof(sock_client));
            mc->ret = accept(mc->args[0] /* fd */,
                             (struct sockaddr *) &sock_client,
                             (socklen_t *) mc->payload[0] /* len */);

            log(SYS, "accept socket done");
            break;
        }
        case 204:
            break;
        case SYSCALL_SEND: {
            log(SYS, "begin to send information");

            char *str = (char *) mc->payload[0];
            int  len  = mc->args[2];

            char     str_real[len + 1];
            for (int i    = 0; i < len; i++) {
                str_real[i] = str[i];
            }
            str_real[len] = '\0';

            mc->ret = send(mc->args[0] /* fd */,
                           str_real,
                           len,
                           mc->args[3] /* flag */);

            log(SYS, "already send information %s", str_real);
            log(SYS, "already send information number %ld", mc->ret);
            break;
        }
        case SYSCALL_RECV: {
            log(SYS, "begin to receive information");

            int  len = mc->args[2];
            char recvbuf[len];
            memset(recvbuf, 0, len);
            mc->ret = recv(mc->args[0] /* fd */,
                           recvbuf,
                           len,
                           mc->args[3] /* flag */);
            memmove(mc->payload[0], recvbuf, len);

            log(SYS, "already receive %ld bytes of information: %s", mc->ret, recvbuf);
            break;
        }
        default:
            break;
    }

    mc->state = STATE_RESPONSE;

    log(SYS, "set mc [ at:%p ] state to response", mc);

    if (mc->ret < 0) perror("errno");

    return (mc->ret == -1 ? -errno : mc->ret);
}


int
main() {
    int       shm_fd   = shm_open("shm_qemu2", O_CREAT | O_RDWR, 0666);
    assert(shm_fd != -1);
    const int shm_size = 4096 * 64;
    ftruncate(shm_fd, shm_size);
    assert(shm_fd != -1);
    void *ptr = mmap(0, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);

    meta_t *meta     = smr_init(ptr, shm_size);
    term_t *terminal = &meta->terminal;
    mc_t   *mc;

    log(SYS, "Terminal [ at:%p ]", terminal);

    while (TRUE) {
        while (!(mc = (mc_t *) dequeue(terminal)));

        handle_syscall(mc);
    }

    return EXIT_SUCCESS;
}