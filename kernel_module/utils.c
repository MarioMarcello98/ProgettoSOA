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

int create_snapshot_directory(void)
{
    struct path path;
    struct inode *inode_dir;
    struct dentry *dentry;
    int ret;

    // Controlla se la directory principale esiste
    ret = kern_path("/prova1", LOOKUP_DIRECTORY, &path);
    if (ret == 0) {
        pr_info("[snapshot] La directory /prova1 esiste già\n");
        path_put(&path);
        return 0;
    }

    pr_info("[snapshot] La directory /prova1 non esiste, la creo\n");

    // Trova la root "/"
    ret = kern_path("/", LOOKUP_DIRECTORY, &path);
    if (ret != 0) {
        pr_err("[snapshot] Errore nel trovare la root /\n");
        return ret;
    }

    // Crea la directory /prova1
    inode_dir = d_inode(path.dentry);
    dentry = d_alloc_name(path.dentry, "prova1");
    if (!dentry) {
        pr_err("[snapshot] Impossibile allocare dentry per /prova1\n");
        path_put(&path);
        return -ENOMEM;
    }

    ret = vfs_mkdir(mnt_idmap(path.mnt), inode_dir, dentry, 0755);
    if (ret != 0) {
        pr_err("[snapshot] Creazione /prova1 fallita: %d\n", ret);
        dput(dentry);
        path_put(&path);
        return ret;
    }

    pr_info("[snapshot] Directory /prova1 creata con successo\n");

    dput(dentry);
    path_put(&path);
    return 0;
}

int create_device_directory(char *dev_name)
{
    struct path path;
    struct inode *inode_dir;
    struct dentry *dentry;
    int ret;
    char dir_name[256];
    struct timespec64 ts;

    // Genera il nome della sottodirectory con timestamp
    ktime_get_real_ts64(&ts);
    snprintf(dir_name, sizeof(dir_name), "/prova1/%s_%lld%02lld%02lld_%02lld%02lld%02lld",
             dev_name,
             (s64)(ts.tv_sec / 31556952 + 1970),
             (s64)((ts.tv_sec / 2629746) % 12 + 1),
             (s64)((ts.tv_sec / 86400) % 31 + 1),
             (s64)((ts.tv_sec / 3600) % 24),
             (s64)((ts.tv_sec / 60) % 60),
             (s64)(ts.tv_sec % 60));

    // Controlla se la directory principale esiste
    ret = kern_path("/prova1", LOOKUP_DIRECTORY, &path);
    if (ret != 0) {
        pr_err("[snapshot] La directory /prova1 non esiste. Assicurati di chiamare create_main_directory prima!\n");
        return ret;
    }

    // Crea la sottodirectory
    inode_dir = d_inode(path.dentry);
    dentry = d_alloc_name(path.dentry, dir_name + strlen("/prova1/"));
    if (!dentry) {
        pr_err("[snapshot] Errore allocando la dentry per %s\n", dir_name);
        path_put(&path);
        return -ENOMEM;
    }

    ret = vfs_mkdir(mnt_idmap(path.mnt), inode_dir, dentry, 0755);
    if (ret != 0) {
        pr_err("[snapshot] Errore nella creazione della directory %s: %d\n", dir_name, ret);
        dput(dentry);
        path_put(&path);
        return ret;
    }

    pr_info("[snapshot] Sottodirectory '%s' creata con successo\n", dir_name);

    dput(dentry);
    path_put(&path);
    return 0;
}