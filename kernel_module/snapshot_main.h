#ifndef SNAPSHOT_H
#define SNAPSHOT_H
#define DEVICE_NAME "snap_device"
#define SNAPSHOT_IOCTL_ACTIVATE   _IOW('s', 1, struct snapshot_req)
#define SNAPSHOT_IOCTL_DEACTIVATE _IOW('s', 2, struct snapshot_req)

struct snapshot_req {
    char dev_name[128];
    char password[128];
};

struct mount_probe_data {
    char dev_name[NAME_MAX];
};

int activate_snapshot(char *dev_name, char *passwd);
int deactivate_snapshot(char *dev_name, char *passwd);
long snapshot_ioctl(struct file *file, unsigned int cmd, unsigned long arg);


#ifdef CONFIG_COMPAT
long snapshot_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
#endif


#endif 