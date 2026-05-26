#include "sl_pidfile.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

int sl_pidfile_write(const char *path) {
    if (!path) return -1;
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        close(fd);
        return -1;
    }

    if (ftruncate(fd, 0) != 0) { close(fd); return -1; }

    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
    if (n <= 0) { close(fd); return -1; }
    if (write(fd, buf, (size_t)n) != n) { close(fd); return -1; }

    /* Intentionally leak fd so the lock is held for the process lifetime. */
    return 0;
}

pid_t sl_pidfile_read(const char *path) {
    if (!path) return 0;
    FILE *fp = fopen(path, "r");
    if (!fp) return 0;
    long pid = 0;
    if (fscanf(fp, "%ld", &pid) != 1) pid = 0;
    fclose(fp);
    return (pid_t)pid;
}

bool sl_pidfile_check_stale(const char *path) {
    pid_t pid = sl_pidfile_read(path);
    if (pid <= 0) return true;
    if (kill(pid, 0) == 0) return false;
    return (errno == ESRCH);
}

void sl_pidfile_remove(const char *path) {
    if (path) unlink(path);
}
