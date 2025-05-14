#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>        
#include <linux/time.h>       
#include <linux/path.h>       
#include <linux/cred.h>       
#include <linux/slab.h>       
#include <linux/namei.h>      
#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcello Mario");

struct list_head snapshot_list = LIST_HEAD_INIT(snapshot_list);
struct mutex snapshot_mutex = __MUTEX_INITIALIZER(snapshot_mutex);

bool is_root_user(void) {
    return (current_euid().val == 0);
}

bool password_valid(const char *passwd) {
    return strcmp(passwd, SNAPSHOT_PASSWORD) == 0;
}

int add_snapshot_device(const char *dev_name) {
    struct snapshot_entry *entry;

    entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return -ENOMEM;

    strncpy(entry->dev_name, dev_name, MAX_DEV_NAME_LEN - 1);
    entry->dev_name[MAX_DEV_NAME_LEN - 1] = '\0';

    mutex_lock(&snapshot_mutex);
    list_add(&entry->list, &snapshot_list);
    mutex_unlock(&snapshot_mutex);

    pr_info("[snapshot] Dispositivo '%s' aggiunto alla lista snapshot attivi\n", dev_name);
    return 0;
}

int remove_snapshot_device(const char *dev_name) {
    struct snapshot_entry *entry, *tmp;
    int found = 0;

    mutex_lock(&snapshot_mutex);
    list_for_each_entry_safe(entry, tmp, &snapshot_list, list) {
        if (strcmp(entry->dev_name, dev_name) == 0) {
            list_del(&entry->list);
            kfree(entry);
            found = 1;
            pr_info("[snapshot] Dispositivo '%s' rimosso dalla lista snapshot attivi\n", dev_name);
            break;
        }
    }
    mutex_unlock(&snapshot_mutex);

    return found ? 0 : -ENOENT;
}

bool is_snapshot_active(const char *dev_name) {
    struct snapshot_entry *entry;
    bool found = false;

    mutex_lock(&snapshot_mutex);
    list_for_each_entry(entry, &snapshot_list, list) {
        if (strcmp(entry->dev_name, dev_name) == 0) {
            found = true;
            break;
        }
    }
    mutex_unlock(&snapshot_mutex);

    return found;
}

int create_snapshot_directory(const char *path_str)
{
    struct path existing_path;
    struct path path;
    struct dentry *dentry;
    struct mnt_idmap *idmap;
    int mode = S_IFDIR | 0755;
    int ret;

    ret = kern_path(path_str, LOOKUP_FOLLOW, &existing_path);
    if (ret == 0) {
        if (d_is_dir(existing_path.dentry)) {
            pr_info("[fs_helper] La directory %s esiste già\n", path_str);
            path_put(&existing_path);
            return 0;
        } else {
            pr_err("[fs_helper] %s esiste ma non è una directory\n", path_str);
            path_put(&existing_path);
            return -ENOTDIR;
        }
    }

    dentry = kern_path_create(AT_FDCWD, path_str, &path, LOOKUP_DIRECTORY);
    if (IS_ERR(dentry)) {
        pr_err("[fs_helper] Errore nella preparazione della creazione della directory %s\n", path_str);
        return PTR_ERR(dentry);
    }

    idmap = mnt_idmap(path.mnt);

    ret = vfs_mkdir(idmap, d_inode(path.dentry), dentry, mode);
    if (ret < 0) {
        pr_err("[fs_helper] Errore nella creazione della directory %s: %d\n", path_str, ret);
    } else {
        pr_info("[fs_helper] Directory %s creata correttamente\n", path_str);
    }

    done_path_create(&path, dentry);
    return ret;
}

int create_device_directory(const char *dev_name)
{
    char full_path[300];
    struct timespec64 ts;
    struct tm tm;

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);

    snprintf(full_path, sizeof(full_path),
             "/prova2/%s_%04ld%02d%02d_%02d%02d%02d",
             dev_name,
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);

    pr_info("[snapshot] Creo directory snapshot: %s\n", full_path);
    return create_snapshot_directory(full_path);
}

char *normalize_dev_name(const char *dev_name)
{
    char *normalized_name;

    normalized_name = kzalloc(MAX_DEV_NAME_LEN, GFP_KERNEL);
    if (!normalized_name)
        return NULL;

    if (strncmp(dev_name, "/dev/", 5) != 0) {
        snprintf(normalized_name, MAX_DEV_NAME_LEN, "/dev/%s", dev_name);
    } else {
        strscpy(normalized_name, dev_name, MAX_DEV_NAME_LEN);
    }
    return normalized_name;
}

void mkdir_work_func(struct work_struct *work)
{
    struct mkdir_work *mw = container_of(work, struct mkdir_work, work);
    create_device_directory(mw->dir_name);  
    kfree(mw);
}

void schedule_mkdir(const char *name)
{
    struct mkdir_work *mw = kmalloc(sizeof(*mw), GFP_KERNEL);
    if (!mw)
        return;

    INIT_WORK(&mw->work, mkdir_work_func);
    strscpy(mw->dir_name, name, NAME_MAX);
    queue_work(snapshot_wq, &mw->work);
}

void adjust_dev_name(char *name) {
    char *p = name;
    while (*p) {
        if (*p == '/')
            *p = '_';
        p++;
    }
}

void snapshot_write_worker(struct work_struct *work) {
    struct snapshot_write_work *sw = container_of(work, struct snapshot_write_work, work);

    char *dir_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!dir_path)
        goto out;

    const char *snapshot_dir = find_latest_snapshot_dir(sw->dev_name);
    if (!snapshot_dir)
        goto out_free_path;

    snprintf(dir_path, PATH_MAX, "%s/blk_%llu", snapshot_dir, (unsigned long long)sw->sector);

    // Verifica se il file esiste già (abbiamo già salvato il blocco)
    struct file *check = filp_open(dir_path, O_RDONLY, 0);
    if (!IS_ERR(check)) {
        filp_close(check, NULL);
        pr_warn("[snapshot] blocco già salvato");
        goto out_free_path;
    }

    // Scrive il blocco originale
    struct file *file = filp_open(dir_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (!IS_ERR(file)) {
        kernel_write(file, sw->data, sw->len, 0);
        filp_close(file, NULL);
    } else {
        pr_warn("[snapshot] filp_open fallita per %s\n", dir_path);
    }

out_free_path:
    kfree(dir_path);
out:
    kfree(sw->data);
    kfree(sw);
}






static bool snapshot_filldir(struct dir_context *ctx, const char *name, int namlen,
                             loff_t offset, u64 ino, unsigned int d_type)
{
    struct snapshot_lookup_ctx *lookup = container_of(ctx, struct snapshot_lookup_ctx, ctx);

    char prefix[32];
    snprintf(prefix, sizeof(prefix), "_dev_%s_", lookup->dev_name);  

    if (strncmp(name, prefix, strlen(prefix)) == 0) {
        if (strcmp(name, lookup->latest) > 0)
            strscpy(lookup->latest, name, NAME_MAX);
    }

    return true;
}

char *find_latest_snapshot_dir(const char *dev_name)
{
    static char result_path[PATH_MAX];
    struct file *dir;

    struct snapshot_lookup_ctx lookup = {
        .ctx.actor = snapshot_filldir,
        .ctx.pos = 0,
        .dev_name = dev_name,
        .latest = "",
    };

    dir = filp_open("/prova2", O_RDONLY | O_DIRECTORY, 0);
    if (IS_ERR(dir))
        return NULL;

    iterate_dir(dir, &lookup.ctx);
    filp_close(dir, NULL);

    if (lookup.latest[0] == '\0')
        return NULL;

    snprintf(result_path, PATH_MAX, "/prova2/%s", lookup.latest);
    return result_path;
}
