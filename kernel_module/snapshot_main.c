#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h> 
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
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/kprobes.h>
#include <linux/workqueue.h>
#include <linux/uaccess.h>  
#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>

#include "snapshot_main.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcello Mario");
MODULE_DESCRIPTION("Snapshot service for block devices");
MODULE_VERSION("0.1");

static int mount_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int mount_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

static struct kprobe write_kp = {
    .symbol_name = "submit_bio",
};

static struct kretprobe mount_kretprobe = {
    .kp.symbol_name = "path_mount",
    .entry_handler = mount_entry_handler,
    .handler = mount_ret_handler,
    .data_size = sizeof(struct mount_probe_data),
    .maxactive = 20,  
};

static int mount_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
#if defined(__x86_64__)
    const char __user *user_dev_name = (const char __user *)regs->di;
    struct mount_probe_data *data = (struct mount_probe_data *)ri->data;

    if (!user_dev_name) {
        pr_warn("[snapshot] [mount_entry_handler] dev_name è NULL\n");
        return 0;
    }

    strscpy(data->dev_name, user_dev_name, NAME_MAX - 1);
    data->dev_name[NAME_MAX - 1] = '\0';
    pr_info("[snapshot] [mount_entry_handler] dev_name copiato: %s\n", data->dev_name);
#endif
    return 0;
}

static int mount_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    long ret = regs_return_value(regs);
    struct mount_probe_data *data = (struct mount_probe_data *)ri->data;

    pr_info("[snapshot] [mount_ret_handler] mount ret = %ld\n", ret);
    pr_info("[snapshot] [mount_ret_handler] dev_name = %s\n", data->dev_name);

    if (ret == 0) {
        if (is_snapshot_active(data->dev_name)) {
            pr_info("[snapshot] [mount_ret_handler] snapshot attivo per %s\n", data->dev_name);

            char adjusted[NAME_MAX];
            strscpy(adjusted, data->dev_name, NAME_MAX);
            adjust_dev_name(adjusted);
            pr_info("[snapshot] [mount_ret_handler] dev_name normalizzato: %s\n", adjusted);

            char *normalized = normalize_dev_name(data->dev_name); 
            if (!normalized) {
                pr_err("[snapshot] [mount_ret_handler] normalize_dev_name fallita\n");
                return 0;
            }

            struct mkdir_work *mw = kmalloc(sizeof(*mw), GFP_KERNEL);
            if (!mw) {
                kfree(normalized);
                pr_warn("[snapshot] [mount_ret_handler] kmalloc fallita per mkdir_work\n");
                return 0;
            }

            strscpy(mw->adjusted_name, adjusted, NAME_MAX);
            strscpy(mw->original_path, normalized, MAX_DEV_NAME_LEN);
            INIT_WORK(&mw->work, mkdir_work_func);
            queue_work(snapshot_wq, &mw->work);
            pr_info("[snapshot] [mount_ret_handler] mkdir_work schedulato per %s\n", adjusted);

            kfree(normalized);
        } else {
            pr_info("[snapshot] [mount_ret_handler] snapshot NON attivo per %s\n", data->dev_name);
        }
    } else {
        pr_info("[snapshot] [mount_ret_handler] mount fallito, nessuna azione\n");
    }

    return 0;
}

static int write_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
#if defined(__x86_64__)
    struct bio *bio = (struct bio *)regs->di;

    if (!bio || bio_op(bio) != REQ_OP_WRITE)
        return 0;

    struct block_device *bdev = bio->bi_bdev;
    if (!bdev)
        return 0;

    const char *disk_name = bdev->bd_disk->disk_name;
    char dev_path[MAX_DEV_NAME_LEN];
    snprintf(dev_path, MAX_DEV_NAME_LEN, "/dev/%s", disk_name);

    if (!is_snapshot_active(dev_path))
        return 0;

    sector_t sector = bio->bi_iter.bi_sector;
    unsigned int len = bio->bi_iter.bi_size;

    pr_info("[kprobe-snapshot] WRITE intercettata su %s, settore: %llu, dimensione: %u\n",
            dev_path, (unsigned long long)sector, len);

    struct snapshot_write_work *sw = kmalloc(sizeof(*sw), GFP_ATOMIC);
    if (!sw)
        return 0;

    sw->data = NULL;  

    strscpy(sw->dev_name, disk_name, NAME_MAX);
    sw->sector = sector;
    sw->len = len;

    INIT_WORK(&sw->work, modifier_bitmap_worker);
    queue_work(snapshot_wq, &sw->work);
#endif
    return 0;
}

static struct class *snapshot_class;
static struct device *snapshot_device;
static dev_t devt;
static struct cdev snapshot_cdev;

static struct file_operations snapshot_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = snapshot_ioctl,
#ifdef CONFIG_COMPAT
    .compat_ioctl = snapshot_compat_ioctl,
#endif
};

long snapshot_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct snapshot_req req;

    pr_info("[snapshot] ioctl chiamato: cmd=0x%08x\n", cmd); 

    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
        pr_warn("[snapshot] Errore nella copia dei dati utente\n");
        return -EFAULT;
    }

    switch (cmd) {
        case SNAPSHOT_IOCTL_ACTIVATE:
            pr_info("[snapshot] Attivazione snapshot per %s\n", req.dev_name);  
            return activate_snapshot(req.dev_name, req.password);

        case SNAPSHOT_IOCTL_DEACTIVATE:
            pr_info("[snapshot] Disattivazione snapshot per %s\n", req.dev_name);  
            return deactivate_snapshot(req.dev_name, req.password);

        default:
            return -EINVAL;
    }
}
#ifdef CONFIG_COMPAT
long snapshot_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    return snapshot_ioctl(file, cmd, arg);
}
#endif

int activate_snapshot(char *dev_name, char *passwd) {
    int ret;
    char *normalized_dev_name;

    if (!is_root_user()) {
        pr_warn("[snapshot] Operazione non permessa: solo root può attivare snapshot\n");
        return -EPERM;
    }

    if (!password_valid(passwd)) {
        pr_warn("[snapshot] Password errata\n");
        return -EACCES;
    }

    normalized_dev_name = normalize_dev_name(dev_name);
    if (!normalized_dev_name) {
        pr_err("[snapshot] Errore nella normalizzazione del nome del dispositivo\n");
        return -EINVAL;
    }

    if (is_snapshot_active(normalized_dev_name)) {
        pr_warn("[snapshot] Snapshot già attivo per %s\n", normalized_dev_name);
        kfree(normalized_dev_name);
        return -EEXIST;
    }

    ret = add_snapshot_device(normalized_dev_name);
    kfree(normalized_dev_name);
    if (ret < 0) {
        pr_err("[snapshot] Errore nell'aggiunta alla lista snapshot: %s\n", dev_name);
        return ret;
    }

    pr_info("[snapshot] Snapshot attivato correttamente per %s\n", dev_name);
    return 0;
}

int deactivate_snapshot(char *dev_name, char *passwd) {
    int ret;
    char *normalized_dev_name;

    if (!is_root_user()) {
        pr_warn("[snapshot] Operazione non permessa: solo root può disattivare snapshot\n");
        return -EPERM;
    }

    if (!password_valid(passwd)) {
        pr_warn("[snapshot] Password errata\n");
        return -EACCES;
    }

    normalized_dev_name = normalize_dev_name(dev_name);
    if (!normalized_dev_name) {
        pr_err("[snapshot] Errore nella normalizzazione del nome del dispositivo\n");
        return -EINVAL;
    }

    if (!is_snapshot_active(normalized_dev_name)) {
        pr_warn("[snapshot] Nessuno snapshot attivo per %s\n", normalized_dev_name);
        kfree(normalized_dev_name);
        return -ENOENT;
    }

    ret = remove_snapshot_device(normalized_dev_name);
    kfree(normalized_dev_name);
    if (ret < 0) {
        pr_err("[snapshot] Errore nella rimozione dello snapshot per %s\n", dev_name);
        return ret;
    }

    pr_info("[snapshot] Snapshot disattivato per %s\n", dev_name);
    return 0;
}

static int __init snapshot_init(void)
{
    int ret;
    ret = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME); 
    if (ret < 0) {
        pr_err("[snapshot] Errore nell'allocazione del numero maggiore\n");
        return ret;
    }

    snapshot_class = class_create(DEVICE_NAME);
    if (IS_ERR(snapshot_class)) {
        pr_err("[snapshot] Errore nella creazione della classe\n");
        unregister_chrdev_region(devt, 1);
        return PTR_ERR(snapshot_class);
    }

    snapshot_device = device_create(snapshot_class, NULL, devt, NULL, DEVICE_NAME);
    if (IS_ERR(snapshot_device)) {
        pr_err("[snapshot] Errore nella creazione del dispositivo\n");
        class_destroy(snapshot_class);
        unregister_chrdev_region(devt, 1);
        return PTR_ERR(snapshot_device);
    }
    cdev_init(&snapshot_cdev, &snapshot_fops);
    ret = cdev_add(&snapshot_cdev, devt, 1);
    if (ret < 0) {
        pr_err("[snapshot] Errore nell'aggiunta del cdev\n");
        device_destroy(snapshot_class, devt);
        class_destroy(snapshot_class);
        unregister_chrdev_region(devt, 1);
        return ret;
    }
    snapshot_wq = alloc_workqueue("snapshot_wq", WQ_UNBOUND | WQ_HIGHPRI, 0);
    if (!snapshot_wq){
        return -ENOMEM;
    }


    ret = register_kretprobe(&mount_kretprobe);
    if (ret < 0) {
        pr_err("[snapshot] Errore nella registrazione del kretprobe su path_mount: %d\n", ret);
        device_destroy(snapshot_class, devt);
        class_destroy(snapshot_class);
        unregister_chrdev_region(devt, 1);
        return ret;
    }
    pr_info("[snapshot] kretprobe registrato su %s\n", mount_kretprobe.kp.symbol_name);


    write_kp.pre_handler = write_handler_pre,
    ret = register_kprobe(&write_kp);
    if (ret < 0) {
        pr_err("[snapshot] Errore registrazione write_kp\n");
        return ret;
    }
    
    create_snapshot_directory("/snapshot");

    pr_info("[snapshot] Modulo caricato, dispositivo %s creato\n", DEVICE_NAME);
    return 0;
}


static void __exit snapshot_exit(void)
{
    unregister_kretprobe(&mount_kretprobe);
    unregister_kprobe(&write_kp);
    cdev_del(&snapshot_cdev);
    device_destroy(snapshot_class, devt);
    class_destroy(snapshot_class);
    unregister_chrdev_region(devt, 1);
    destroy_workqueue(snapshot_wq);

    pr_info("[snapshot] Modulo scaricato\n");
}

module_init(snapshot_init);
module_exit(snapshot_exit);