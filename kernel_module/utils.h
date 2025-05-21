#ifndef UTILS_H
#define UTILS_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/types.h> 

#define MAX_DEV_NAME_LEN 64
#define SNAPSHOT_PASSWORD "12345"
#define SNAPSHOT_BLOCK_SIZE 4096

struct snapshot_entry {
    char dev_name[MAX_DEV_NAME_LEN];
    struct list_head list;
};

extern struct workqueue_struct *snapshot_wq;

struct snapshot_write_work {
    struct work_struct work;
    char dev_name[NAME_MAX];
    sector_t sector;
    unsigned int len;
    char *data;
};

struct mkdir_work {
    struct work_struct work;
    char adjusted_name[NAME_MAX];   // per creare la directory
    char original_path[MAX_DEV_NAME_LEN];  // per filp_open
};


struct snapshot_lookup_ctx {
    struct dir_context ctx;
    const char *dev_name;
    char latest[NAME_MAX];
};

struct snapshot_copy_work {
    struct work_struct work;
    char dev_name[NAME_MAX];
    char snapshot_dir[PATH_MAX];
};

extern struct list_head snapshot_list;
extern struct mutex snapshot_mutex;


bool is_root_user(void);
bool password_valid(const char *passwd);
int add_snapshot_device(const char *dev_name);
int remove_snapshot_device(const char *dev_name);
bool is_snapshot_active(const char *dev_name);
int create_snapshot_directory(const char *path_str);
int create_device_directory(const char *dev_name, char *out_path, size_t out_size);
void adjust_dev_name(char *name);
void schedule_mkdir(const char *adjusted_name, const char *original_path);
char *normalize_dev_name(const char *dev_name);
void mkdir_work_func(struct work_struct *work);
void snapshot_write_worker(struct work_struct *work);
char *find_latest_snapshot_dir(const char *dev_name);
void snapshot_copy_worker(struct work_struct *work);



#endif 