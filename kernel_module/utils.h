#ifndef UTILS_H
#define UTILS_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h> 

#define MAX_DEV_NAME_LEN 64
#define SNAPSHOT_PASSWORD "12345"

struct snapshot_entry {
    char dev_name[MAX_DEV_NAME_LEN];
    struct list_head list;
};

extern struct list_head snapshot_list;
extern struct mutex snapshot_mutex;


bool is_root_user(void);
bool password_valid(const char *passwd);
int add_snapshot_device(const char *dev_name);
int remove_snapshot_device(const char *dev_name);
bool is_snapshot_active(const char *dev_name);
int create_snapshot_directory(const char *path_str);
int create_device_directory(char *dev_name);


#endif 
