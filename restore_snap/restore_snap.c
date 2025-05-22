#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

#define SNAPSHOT_BLOCK_SIZE 4096
#define SNAPSHOT_DIR "/prova2"
#define BITMAP_FILE "mod_bitmap.bin"

char *find_latest_snapshot_dir(const char *dev_name) {
    static char latest_path[PATH_MAX] = {0};
    DIR *dir = opendir(SNAPSHOT_DIR);
    if (!dir)
        return NULL;

    struct dirent *entry;
    time_t latest_time = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR || entry->d_name[0] == '.')
            continue;

        if (!strstr(entry->d_name, dev_name))
            continue;

        char full_path[PATH_MAX];
        snprintf(full_path, PATH_MAX, "%s/%s", SNAPSHOT_DIR, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == 0 && st.st_mtime > latest_time) {
            latest_time = st.st_mtime;
            snprintf(latest_path, PATH_MAX, "%s", full_path);
        }
    }

    closedir(dir);
    return latest_path[0] ? latest_path : NULL;
}

int restore_blocks(const char *device_path, const char *dev_name) {
    char *snap_dir = find_latest_snapshot_dir(dev_name);
    if (!snap_dir) {
        fprintf(stderr, "Nessuna snapshot trovata per %s\n", dev_name);
        return -1;
    }

    char bitmap_path[PATH_MAX];
    snprintf(bitmap_path, PATH_MAX, "%s/%s", snap_dir, BITMAP_FILE);

    int bmp_fd = open(bitmap_path, O_RDONLY);
    if (bmp_fd < 0) {
        perror("Impossibile aprire bitmap");
        return -1;
    }

    int dev_fd = open(device_path, O_WRONLY);
    if (dev_fd < 0) {
        perror("Errore apertura device");
        close(bmp_fd);
        return -1;
    }



    uint8_t byte;
    size_t block_index = 0;
    ssize_t r;
    char blk_path[PATH_MAX];
    uint8_t buffer[SNAPSHOT_BLOCK_SIZE];

    while ((r = read(bmp_fd, &byte, 1)) == 1) {
        for (int bit = 0; bit < 8; bit++) {
            if (byte & (1 << bit)) {
                size_t blk = block_index + bit;
                snprintf(blk_path, PATH_MAX, "%s/blk_%zu", snap_dir, blk);

                int blk_fd = open(blk_path, O_RDONLY);
                if (blk_fd < 0) {
                    fprintf(stderr, "Blocco mancante: %s\n", blk_path);
                    continue;
                }

                ssize_t read_len = read(blk_fd, buffer, SNAPSHOT_BLOCK_SIZE);
                close(blk_fd);

                if (read_len > 0) {
                    off_t offset = blk * SNAPSHOT_BLOCK_SIZE;
                    if (pwrite(dev_fd, buffer, read_len, offset) != read_len) {
                        perror("Errore scrittura blocco");
                    } else {
                        printf("✔ Ripristinato blocco %zu\n", blk);
                    }
                } else {
                    fprintf(stderr, "Errore lettura blocco %s\n", blk_path);
                }
            }
        }
        block_index += 8;
    }

    close(dev_fd);
    close(bmp_fd);
    return 0;
}

const char *normalize_dev_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s /dev/loopX\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (getuid() != 0) {
        return EXIT_FAILURE;
    }

    const char *device_path = argv[1];
    const char *dev_name = normalize_dev_name(device_path);

    return restore_blocks(device_path, dev_name);
}
