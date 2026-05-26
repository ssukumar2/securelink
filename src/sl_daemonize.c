#include "sl_daemonize.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int redirect_fd(int fd, const char *path, int flags) {
    const char *target = path ? path : "/dev/null";
    int new_fd = open(target, flags, 0644);
    if (new_fd < 0) return -1;
    if (dup2(new_fd, fd) < 0) { close(new_fd); return -1; }
    if (new_fd != fd) close(new_fd);
    return 0;
}

int sl_daemonize(const sl_daemonize_opts_t *opts) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);   /* parent exits */

    if (setsid() < 0) return -1;

    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) _exit(0);   /* intermediate exits */

    umask(0027);

    const char *cwd = (opts && opts->chdir_to) ? opts->chdir_to : "/";
    if (chdir(cwd) != 0) return -1;

    if (opts && opts->close_all_fds) {
        struct rlimit rl;
        long max_fds = 1024;
        if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
            max_fds = (long)rl.rlim_cur;
        }
        for (long fd = 3; fd < max_fds; ++fd) close((int)fd);
    }

    if (redirect_fd(STDIN_FILENO, NULL, O_RDONLY) != 0) return -1;
    if (redirect_fd(STDOUT_FILENO,
                    opts ? opts->stdout_redirect : NULL,
                    O_WRONLY | O_CREAT | O_APPEND) != 0) return -1;
    if (redirect_fd(STDERR_FILENO,
                    opts ? opts->stderr_redirect : NULL,
                    O_WRONLY | O_CREAT | O_APPEND) != 0) return -1;

    return 0;
}
