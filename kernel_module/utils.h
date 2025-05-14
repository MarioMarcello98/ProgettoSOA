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

static struct workqueue_struct *snapshot_wq;

struct snapshot_write_work {
    struct work_struct work;
    char dev_name[NAME_MAX];
    sector_t sector;
    unsigned int len;
    char *data;
};

struct mkdir_work {
    struct work_struct work;
    char dir_name[NAME_MAX];
};

struct snapshot_lookup_ctx {
    struct dir_context ctx;
    const char *dev_name;
    char latest[NAME_MAX];
};

extern struct list_head snapshot_list;
extern struct mutex snapshot_mutex;


bool is_root_user(void);
bool password_valid(const char *passwd);
int add_snapshot_device(const char *dev_name);
int remove_snapshot_device(const char *dev_name);
bool is_snapshot_active(const char *dev_name);
int create_snapshot_directory(const char *path_str);
int create_device_directory(const char *dev_name);
void adjust_dev_name(char *name);
void schedule_mkdir(const char *name);
char *normalize_dev_name(const char *dev_name);
void mkdir_work_func(struct work_struct *work);
void snapshot_write_worker(struct work_struct *work);
char *find_latest_snapshot_dir(const char *dev_name);



#endif 
