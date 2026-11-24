#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <sys/stat.h>

/* minimal fanotify FIM monitor: report create/modify/delete/move + sha256 */

static void sha256_file(const char *path, char out[65]) {
    char cmd[512];
    out[0] = 0;
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null | awk '{print $1}'", path);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        if (fgets(out, 65, fp) == NULL) out[0] = 0;
        pclose(fp);
    }
}

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "/tmp/fim_test";
    mkdir(path, 0755);

    int fd = fanotify_init(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY);
    if (fd < 0) { perror("fanotify_init"); return 1; }
    if (fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
            FAN_MODIFY | FAN_CLOSE_WRITE | FAN_OPEN,
            AT_FDCWD, path) < 0) {
        perror("fanotify_mark"); return 1;
    }
    printf("FIM monitoring: %s\n", path);
    fflush(stdout);

    char buf[8192];
    while (1) {
        ssize_t len = read(fd, buf, sizeof(buf));
        if (len < 0) { if (errno == EAGAIN) { usleep(100000); continue; } perror("read"); break; }
        struct fanotify_event_metadata *meta = (struct fanotify_event_metadata *)buf;
        while (FAN_EVENT_OK(meta, len)) {
            if (meta->vers != FANOTIFY_METADATA_VERSION) { fprintf(stderr, "bad version\n"); return 1; }
            char linkbuf[64], resolved[256] = "(deleted)";
            snprintf(linkbuf, sizeof(linkbuf), "/proc/self/fd/%d", meta->fd);
            ssize_t rl = readlink(linkbuf, resolved, sizeof(resolved)-1);
            if (rl > 0) resolved[rl] = 0;

            const char *ev = "?";
            if (meta->mask & FAN_MODIFY) ev = "MODIFY";
            else if (meta->mask & FAN_CLOSE_WRITE) ev = "CLOSE_WRITE";
            else if (meta->mask & FAN_OPEN) ev = "OPEN";

            char hash[65] = "-";
            if ((meta->mask & (FAN_CLOSE_WRITE|FAN_MODIFY)) && rl > 0)
                sha256_file(resolved, hash);

            printf("%s path=%s sha256=%s\n", ev, resolved, hash);
            fflush(stdout);
            if (meta->fd != FAN_NOFD) close(meta->fd);
            meta = FAN_EVENT_NEXT(meta, len);
        }
    }
    return 0;
}
