
#include "chris.h"
#include "dev.h"

int chris_major = 0;
int chris_minor = 0;


int chris_open(struct inode *inode, struct file *filp)
{
    struct chris_priv_data_s *priv_data = NULL;
	struct chris_dev_s *chris_dev = container_of(inode->i_cdev, struct chris_dev_s, cdev);

	priv_data->chris_dev = chris_dev;
	
	CHRIS_LOG(KLOG_DEBUG, "\n");

    priv_data = kzalloc(sizeof(struct chris_priv_data_s), GFP_KERNEL);
    RETURN_VAL_DO_INFO_IF_IS_ERR(priv_data, -ENOMEM,
        CHRIS_LOG(KLOG_DEBUG, "priv_data kzalloc failed!\n"););
    
	filp->private_data = priv_data;
    
	return 0;
}

int chris_release(struct inode *inode, struct file *filp)
{
    struct chris_priv_data_s *priv_data = (struct chris_priv_data_s *)filp->private_data;

	CHRIS_LOG(KLOG_DEBUG, "\n");

    filp->private_data = NULL;

    if (priv_data) {
        kfree(priv_data);
    }

    return 0;
}

static ssize_t chris_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
    struct chris_priv_data_s *priv_data = (struct chris_priv_data_s *)filp->private_data;

	priv_data = priv_data;
    
    return 0;
}

static ssize_t chris_write(struct file *filp, const char __user *data, size_t len, loff_t *ppos)
{
    struct chris_priv_data_s *priv_data = (struct chris_priv_data_s *)filp->private_data;

	priv_data = priv_data;

    return len;
}


static int chris_mmap(struct file *filp, struct vm_area_struct *vma)
{
    struct chris_priv_data_s *priv_data = (struct chris_priv_data_s *)filp->private_data;

	priv_data = priv_data;


    return 0;
}


static int chris_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct chris_priv_data_s *priv_data = (struct chris_priv_data_s *)filp->private_data;

	priv_data = priv_data;

 
    return 0;
}


static unsigned int chris_poll(struct file * filp, poll_table *wait) 
{
    struct chris_priv_data_s *priv_data = filp->private_data;
	struct chris_dev_s *chris_dev = priv_data->chris_dev;
	unsigned int mask = 0;

	poll_wait(filp, &chris_dev->wait, wait);
    //if (list->head != list->tail)
    //{
    //    mask |= POLLIN | POLLRDNORM;
    //}

    return 0;
}

static int chris_fasync(int fd, struct file *filp, int mode)
{
    struct chris_priv_data_s *priv_data = filp->private_data;
	struct chris_dev_s *chris_dev = priv_data->chris_dev;

	priv_data = priv_data;

    return fasync_helper(fd, filp, mode, &chris_dev->async_queue);
}



struct file_operations chris_fops = {
	.owner = THIS_MODULE,
	.open = chris_open,
	.release = chris_release,
	.read = chris_read,
    .write = chris_write,
    .unlocked_ioctl = chris_ioctl,
    .compat_ioctl = chris_ioctl,
    .poll = chris_poll,
    .fasync = chris_fasync,
    .mmap = chris_mmap,
};


static int chris_setup_cdev(struct chris_dev_s *dev, int major, int index)
{
    int ret, devno = MKDEV(major, index);

    cdev_init(&dev->cdev, &chris_fops);    

    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &chris_fops;

    ret = cdev_add(&dev->cdev, devno, 1);
	RETURN_VAL_DO_INFO_IF_FAIL(!ret, ret, 
        CHRIS_LOG(KLOG_DEBUG, "cdev_add failed! ret = %d\n", ret););

	return 0;
}


struct chris_dev_s *dev_init(void)
{
    int ret = 0;
    int i = 0;
    dev_t devno = 0;
    struct chris_dev_s *chris_dev = NULL;

	if (chris_major) 
    {     
        devno = MKDEV(chris_major, chris_minor); 
        ret = register_chrdev_region(devno, CHRIS_DEVICE_NUM, "chris");
		RETURN_VAL_DO_INFO_IF_FAIL(!ret, ERR_PTR(ret), 
        	CHRIS_LOG(KLOG_DEBUG, "alloc_chrdev_region failed! ret = %d\n", ret););
    } 
    else 
    {        
        ret = alloc_chrdev_region(&devno, chris_minor, CHRIS_DEVICE_NUM, "chris");
		RETURN_VAL_DO_INFO_IF_FAIL(!ret, ERR_PTR(ret), 
        	CHRIS_LOG(KLOG_DEBUG, "alloc_chrdev_region failed! ret = %d\n", ret););
		
        CHRIS_LOG(KLOG_DEBUG, "major = %d\n", MAJOR(devno));
        chris_major = MAJOR(devno);
    }	

    chris_dev = kzalloc(sizeof(struct chris_dev_s) * CHRIS_DEVICE_NUM, GFP_KERNEL);
    DO_INFO_IF_EXPR_IS_ERR(chris_dev, 
        CHRIS_LOG(KLOG_DEBUG, "chris_dev kzalloc failed! \n"); ret = -ENOMEM; goto fail);


    for (i = 0; i < CHRIS_DEVICE_NUM; i++) {
        ret = chris_setup_cdev(chris_dev + i, MAJOR(devno), i);
        DO_INFO_IF_EXPR_UNLIKELY(!ret,
            CHRIS_LOG(KLOG_DEBUG, "chris_setup_cdev failed! \n"); goto fail);
    }

	init_waitqueue_head(&(chris_dev->wait));

    return chris_dev;
    
fail:
    dev_cleanup(chris_dev);
    return ERR_PTR(ret);
}

void dev_cleanup(struct chris_dev_s *chris_dev)
{
    int i = 0;

    if (chris_dev) {
        dev_t devno = chris_dev->cdev.dev;

        for (i = 0; i < CHRIS_DEVICE_NUM; i++) {
            cdev_del(&(chris_dev + i)->cdev);
        }
        unregister_chrdev_region(devno, CHRIS_DEVICE_NUM);
        kfree(chris_dev);
    }
}


