#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>         // vfs_mkdir
#include <linux/time.h>       // ktime_get_real_ts64()
#include <linux/path.h>       // kern_path
#include <linux/cred.h>       // current_euid()
#include <linux/slab.h>       // kmalloc e kfree
#include <linux/namei.h>      // kern_path
#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include "snapshot_main.h"
#include "utils.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Marcello Mario");
MODULE_DESCRIPTION("Snapshot service for block devices");
MODULE_VERSION("0.1");

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

// Funzioni init/exit del modulo
static int __init snapshot_init(void)
{
    printk(KERN_INFO "Snapshot module loaded\n");

    // Test della funzione create_snapshot_directory
    char dev_name[] = "loop0"; // Usa un dispositivo di esempio, es. loop0
    char passwd[] = "12345"; // Usa la password corretta

    // Chiamata della funzione activate_snapshot
    int ret = activate_snapshot(dev_name, passwd);
    if (ret == 0) {
        printk(KERN_INFO "[snapshot] Test snapshot attivato con successo.\n");
    } else {
        printk(KERN_ERR "[snapshot] Errore nell'attivazione dello snapshot.\n");
    }

    return 0;
}

static void __exit snapshot_exit(void)
{
    printk(KERN_INFO "[snapshot] Modulo scaricato\n");
}

module_init(snapshot_init);
module_exit(snapshot_exit);
