#include "sl_atomic_file.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int sl_atomic_write_bytes(const char *path,
                          const void *data, size_t len,
                          int do_fsync) {
    if (!path || (!data && len > 0)) return -1;

    char tmp[1024];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;

    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, (const char *)data + off, len - off);
        if (w < 0) { close(fd); unlink(tmp); return -1; }
        off += (size_t)w;
    }
    if (do_fsync) (void)fsync(fd);
    close(fd);

    if (rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int sl_atomic_append_line(const char *path, const char *line) {
    if (!path || !line) return -1;
    const size_t llen = strlen(line);
    char *buf = (char *)malloc(llen + 2);
    if (!buf) return -1;
    memcpy(buf, line, llen);
    buf[llen]     = '\n';
    buf[llen + 1] = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { free(buf); return -1; }
    ssize_t w = write(fd, buf, llen + 1);
    close(fd);
    free(buf);
    return (w == (ssize_t)(llen + 1)) ? 0 : -1;
}

int sl_read_all(const char *path, uint8_t **out_data, size_t *out_len) {
    if (!path || !out_data || !out_len) return -1;
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    long sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    rewind(fp);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf && sz > 0) { fclose(fp); return -1; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return -1;
    }
    fclose(fp);
    *out_data = buf;
    *out_len  = (size_t)sz;
    return 0;
}
