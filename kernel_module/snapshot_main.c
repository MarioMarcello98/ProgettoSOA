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
#include "snapshot_main.h"
#include "utils.h"
#include <linux/fs.h>         
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcello Mario");
MODULE_DESCRIPTION("Snapshot service for block devices");
MODULE_VERSION("0.1");



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


#include <linux/uaccess.h>  // Assicurati di avere questa per copy_from_user

long snapshot_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct snapshot_req req;

    pr_info("[snapshot] ioctl chiamato: cmd=0x%08x\n", cmd);  // Aggiungi un log

    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
        pr_warn("[snapshot] Errore nella copia dei dati utente\n");
        return -EFAULT;
    }

    switch (cmd) {
        case SNAPSHOT_IOCTL_ACTIVATE:
            pr_info("[snapshot] Attivazione snapshot per %s\n", req.dev_name);  // Aggiungi log
            return activate_snapshot(req.dev_name, req.password);

        case SNAPSHOT_IOCTL_DEACTIVATE:
            pr_info("[snapshot] Disattivazione snapshot per %s\n", req.dev_name);  // Aggiungi log
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

    if (!is_root_user()) {
        pr_warn("[snapshot] Operazione non permessa: solo root può attivare snapshot\n");
        return -EPERM;
    }

    if (!password_valid(passwd)) {
        pr_warn("[snapshot] Password errata\n");
        return -EACCES;
    }

    if (is_snapshot_active(dev_name)) {
        pr_warn("[snapshot] Snapshot già attivo per %s\n", dev_name);
        return -EEXIST;
    }

    pr_info("[snapshot] Attivazione snapshot per %s\n", dev_name);

    ret = create_snapshot_directory(dev_name);
    if (ret < 0) {
        pr_err("[snapshot] Creazione directory snapshot fallita per %s\n", dev_name);
        return ret;
    }

    ret = add_snapshot_device(dev_name);
    if (ret < 0) {
        pr_err("[snapshot] Errore nell'aggiunta alla lista snapshot: %s\n", dev_name);
        return ret;
    }

    pr_info("[snapshot] Snapshot attivato correttamente per %s\n", dev_name);
    return 0;
}

int deactivate_snapshot(char *dev_name, char *passwd) {
    int ret;

    if (!is_root_user()) {
        pr_warn("[snapshot] Operazione non permessa: solo root può disattivare snapshot\n");
        return -EPERM;
    }

    if (!password_valid(passwd)) {
        pr_warn("[snapshot] Password errata\n");
        return -EACCES;
    }

    if (!is_snapshot_active(dev_name)) {
        pr_warn("[snapshot] Nessuno snapshot attivo per %s\n", dev_name);
        return -ENOENT;
    }

    ret = remove_snapshot_device(dev_name);
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

    // Registrazione del dispositivo
    ret = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME); // allocazione automatica del major number
    if (ret < 0) {
        pr_err("[snapshot] Errore nell'allocazione del numero maggiore\n");
        return ret;
    }

    // Creazione della classe del dispositivo
    snapshot_class = class_create(DEVICE_NAME);
    if (IS_ERR(snapshot_class)) {
        pr_err("[snapshot] Errore nella creazione della classe\n");
        unregister_chrdev_region(devt, 1);
        return PTR_ERR(snapshot_class);
    }

    // Creazione del dispositivo
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

    pr_info("[snapshot] Modulo caricato, dispositivo %s creato\n", DEVICE_NAME);
    return 0;
}

static void __exit snapshot_exit(void)
{
    cdev_del(&snapshot_cdev);
    device_destroy(snapshot_class, devt);  // Rimuove il dispositivo
    class_destroy(snapshot_class);         // Distrugge la classe
    unregister_chrdev_region(devt, 1);     // Rilascia la regione del dispositivo

    pr_info("[snapshot] Modulo scaricato\n");
}

module_init(snapshot_init);
module_exit(snapshot_exit);
