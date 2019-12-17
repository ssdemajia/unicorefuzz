#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PROCFS_NAME       "buffer10"
#define PROCFS_MAX_SIZE   10

struct proc_dir_entry *entry;

static ssize_t write_callback(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
  char local_buffer[PROCFS_MAX_SIZE*2];
  copy_from_user(local_buffer, ubuf, PROCFS_MAX_SIZE*2);
  if(local_buffer[0] == 'A')
  {
    int a = 2;
    a -= 2;
    if (5/a > 0) {
        printk(KERN_INFO "this will never happen!\n");
    }
  }
  return count;
}

static ssize_t read_callback(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
  return 0;
}

static struct file_operations ops =
{
	.owner = THIS_MODULE,
	.read = read_callback,
	.write = write_callback,
};

static int simple_init(void)
{
  entry = proc_create(PROCFS_NAME, 0644, NULL, &ops);
  printk(KERN_INFO "/proc/%s created\n", PROCFS_NAME);
  return 0;
}

static void simple_cleanup(void)
{
  proc_remove(entry);
  printk(KERN_INFO "/proc/%s removed\n", PROCFS_NAME);
}

module_init(simple_init);
module_exit(simple_cleanup);
MODULE_LICENSE("GPL");
