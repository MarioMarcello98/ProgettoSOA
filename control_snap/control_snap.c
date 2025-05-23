#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#define SNAPSHOT_IOCTL_ACTIVATE   _IOW('s', 1, struct snapshot_req)
#define SNAPSHOT_IOCTL_DEACTIVATE _IOW('s', 2, struct snapshot_req)

struct snapshot_req {
    char dev_name[128];
    char password[128];
};

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Uso: %s <activate|deactivate> <dev_name> <password>\n", argv[0]);
        return 1;
    }

    char *action = argv[1];

    int fd = open("/dev/snap_device", O_RDWR);
    if (fd == -1) {
        perror("Impossibile aprire il dispositivo");
        return 1;
    }

    struct snapshot_req req;
    memset(&req, 0, sizeof(req));
    strncpy(req.dev_name, argv[2], sizeof(req.dev_name) - 1);
    strncpy(req.password, argv[3], sizeof(req.password) - 1);

    if (strcmp(action, "activate") == 0) {
        if (ioctl(fd, SNAPSHOT_IOCTL_ACTIVATE, &req) == -1) {
            perror("Errore nell'attivazione dello snapshot");
            close(fd);
            return 1;
        }
        printf("Snapshot attivato per %s\n", req.dev_name);
    } 

    else if (strcmp(action, "deactivate") == 0) {
        if (ioctl(fd, SNAPSHOT_IOCTL_DEACTIVATE, &req) == -1) {
            perror("Errore nella disattivazione dello snapshot");
            close(fd);
            return 1;
        }
        printf("Snapshot disattivato per %s\n", req.dev_name);
    } else {
        printf("Comando non valido. Usa 'activate' o 'deactivate'.\n");
        close(fd);
        return 1;
    }

    close(fd);
    return 0;
}
