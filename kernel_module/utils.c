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
#include <linux/fs.h>            
#include <linux/blkdev.h>       
#include <linux/bitmap.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>


#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcello Mario");

struct list_head snapshot_list = LIST_HEAD_INIT(snapshot_list);
struct mutex snapshot_mutex = __MUTEX_INITIALIZER(snapshot_mutex);
struct workqueue_struct *snapshot_wq;

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

int create_device_directory(const char *dev_name, char *out_path, size_t out_size)
{
    struct timespec64 ts;
    struct tm tm;

    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);

    snprintf(out_path, out_size,
             "/prova2/%s_%04ld%02d%02d_%02d%02d%02d",
             dev_name,
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour + 2, tm.tm_min, tm.tm_sec);

    pr_info("[snapshot] Creo directory snapshot: %s\n", out_path);
    return create_snapshot_directory(out_path);
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
    char *snapshot_path = kmalloc(PATH_MAX, GFP_KERNEL);

    if (!snapshot_path) {
        pr_err("[snapshot] kmalloc fallita per snapshot_path\n");
        goto cleanup;
    }

    if (create_device_directory(mw->adjusted_name, snapshot_path, PATH_MAX) == 0) {
        pr_info("[snapshot] Directory %s creata correttamente\n", snapshot_path);

        struct snapshot_copy_work *cw = kmalloc(sizeof(*cw), GFP_KERNEL);
        if (!cw) {
            pr_err("[snapshot] kmalloc fallita per copy_work\n");
            goto cleanup_path;
        }

        strscpy(cw->dev_name, mw->original_path, NAME_MAX); 
        strscpy(cw->snapshot_dir, snapshot_path, PATH_MAX);

        INIT_WORK(&cw->work, snapshot_copy_worker);
        queue_work(snapshot_wq, &cw->work);

        pr_info("[snapshot] snapshot_copy_worker schedulato su %s\n", snapshot_path);
    } else {
        pr_err("[snapshot] Errore nella creazione della directory snapshot\n");
    }

cleanup_path:
    kfree(snapshot_path);
cleanup:
    kfree(mw);
}



void schedule_mkdir(const char *adjusted_name, const char *original_path)
{
    struct mkdir_work *mw = kmalloc(sizeof(*mw), GFP_KERNEL);
    if (!mw)
        return;

    INIT_WORK(&mw->work, mkdir_work_func);
    strscpy(mw->adjusted_name, adjusted_name, NAME_MAX);
    strscpy(mw->original_path, original_path, MAX_DEV_NAME_LEN);
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

void snapshot_copy_worker(struct work_struct *work)
{
    struct snapshot_copy_work *cw = container_of(work, struct snapshot_copy_work, work);
    struct file *bdev_file;
    loff_t dev_size, offset = 0;
    char *buf = NULL;
    char *file_path = NULL;
    int ret_bitmap = 0;

    pr_info("[snapshot] [copy_worker] Avvio per %s in %s\n", cw->dev_name, cw->snapshot_dir);

    bdev_file = filp_open(cw->dev_name, O_RDONLY | O_LARGEFILE, 0);
    if (IS_ERR(bdev_file)) {
        pr_err("[snapshot] [copy_worker] filp_open fallita su %s (err: %ld)\n",
               cw->dev_name, PTR_ERR(bdev_file));
        goto out;
    }

    dev_size = i_size_read(bdev_file->f_mapping->host);
    pr_info("[snapshot] [copy_worker] Dimensione del device: %lld bytes\n", dev_size);

    ret_bitmap = snapshot_init_bitmap(cw->snapshot_dir, dev_size, SNAPSHOT_BLOCK_SIZE,
        &cw->mod_bitmap, &cw->total_blocks);
    if (ret_bitmap) {
        pr_err("[snapshot] Errore inizializzazione bitmap: %d\n", ret_bitmap);
        goto close_dev;
    }


    buf = kmalloc(SNAPSHOT_BLOCK_SIZE, GFP_KERNEL);
    if (!buf) {
        pr_err("[snapshot] [copy_worker] kmalloc fallita per buffer\n");
        goto close_dev;
    }

    file_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!file_path) {
        pr_err("[snapshot] [copy_worker] kmalloc fallita per file_path\n");
        goto free_buf;
    }

    while (offset < dev_size) {
        loff_t off = offset;
        int ret_read = kernel_read(bdev_file, buf,SNAPSHOT_BLOCK_SIZE , &off);
        if (ret_read <= 0) {
            pr_err("[snapshot] [copy_worker] Lettura fallita a offset %lld (ret: %d)\n", offset, ret_read);
            break;
        }

        snprintf(file_path, PATH_MAX, "%s/blk_%llu", cw->snapshot_dir, offset / SNAPSHOT_BLOCK_SIZE);
        pr_info("[snapshot] [copy_worker] Scrivo blocco %llu in %s\n", offset / SNAPSHOT_BLOCK_SIZE, file_path);

        struct file *outf = filp_open(file_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (IS_ERR(outf)) {
            pr_err("[snapshot] [copy_worker] filp_open fallita per %s (err: %ld)\n",
                   file_path, PTR_ERR(outf));
            break;
        }

        int ret_write = kernel_write(outf, buf, ret_read, 0);
        if (ret_write < 0) {
            pr_err("[snapshot] [copy_worker] Scrittura fallita su %s (ret: %d)\n",
                   file_path, ret_write);
        }

        filp_close(outf, NULL);
        offset += ret_read;
    }
    pr_info("[snapshot] [copy_worker] Fine copia blocchi per %s\n", cw->dev_name);

    kfree(file_path);
free_buf:
    kfree(buf);
close_dev:
    filp_close(bdev_file, NULL);
out:
    kfree(cw);
}




void modifier_bitmap_worker(struct work_struct *work)
{
    struct snapshot_write_work *sw = container_of(work, struct snapshot_write_work, work);

    const char *snapshot_dir = find_latest_snapshot_dir(sw->dev_name);
    if (!snapshot_dir) {
        pr_err("[snapshot-worker] snapshot_dir non trovato per %s\n", sw->dev_name);
        goto out;
    }

    char *bitmap_path = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!bitmap_path)
        return;

    snprintf(bitmap_path, PATH_MAX, "%s/mod_bitmap.bin", snapshot_dir);

    struct file *bmp_file = filp_open(bitmap_path, O_RDWR, 0);
    if (IS_ERR(bmp_file)) {
        pr_err("[snapshot-worker] Impossibile aprire bitmap: %s\n", bitmap_path);
        goto out;
    }

    unsigned int sectors_per_block = SNAPSHOT_BLOCK_SIZE / 512;
    sector_t start_sector = sw->sector;
    sector_t end_sector = sw->sector + (sw->len / 512) - 1;

    sector_t start_block = start_sector / sectors_per_block;
    sector_t end_block   = end_sector / sectors_per_block;

    for (sector_t blk = start_block; blk <= end_block; blk++) {
        loff_t byte_offset = blk / 8;
        unsigned int bit_pos = blk % 8;
        unsigned char byte;

        // Leggi il byte corrente
        loff_t pos = byte_offset;
        ssize_t ret = kernel_read(bmp_file, &byte, 1, &pos);
        if (ret != 1) {
            pr_warn("[snapshot-worker] errore lettura byte bitmap (blocco %llu)\n", blk);
            continue;
        }

        // Modifica il bit
        byte |= (1 << bit_pos);

        // Scrivi di nuovo il byte
        pos = byte_offset;
        ret = kernel_write(bmp_file, &byte, 1, &pos);
        if (ret != 1) {
            pr_warn("[snapshot-worker] errore scrittura bitmap (blocco %llu)\n", blk);
        } else {
            pr_debug("[snapshot-worker] bit aggiornato su disco per blocco %llu\n", blk);
        }
    }

    filp_close(bmp_file, NULL);

out:
    kfree(sw);
    kfree(bitmap_path);
}




int snapshot_init_bitmap(const char *snapshot_dir, loff_t dev_size, size_t block_size,
    unsigned long **bitmap_out, size_t *total_blocks_out){
    char *bitmap_path = NULL;
    struct file *bmp_file;
    loff_t pos = 0;
    size_t total_blocks, bitmap_size;
    unsigned long *bitmap = NULL;

    if (!snapshot_dir || !bitmap_out || !total_blocks_out)
    return -EINVAL;

    total_blocks = dev_size / block_size;
    bitmap_size = BITS_TO_LONGS(total_blocks) * sizeof(unsigned long);

    bitmap = kzalloc(bitmap_size, GFP_KERNEL);
    if (!bitmap)
    return -ENOMEM;

    bitmap_path = kasprintf(GFP_KERNEL, "%s/mod_bitmap.bin", snapshot_dir);
    if (!bitmap_path) {
    kfree(bitmap);
    return -ENOMEM;
    }

    bmp_file = filp_open(bitmap_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    kfree(bitmap_path);

    if (IS_ERR(bmp_file)) {
    kfree(bitmap);
    return PTR_ERR(bmp_file);
    }   

    kernel_write(bmp_file, (char *)bitmap, bitmap_size, &pos);
    filp_close(bmp_file, NULL);

    *bitmap_out = bitmap;
    *total_blocks_out = total_blocks;
    return 0;
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