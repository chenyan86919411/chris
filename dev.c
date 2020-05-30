
#include "chris.h"
#include "dev.h"


int chris_open(struct inode *inode, struct file *filp)
{
    struct chris_priv_data_s *priv_data = NULL;
	//struct chris_dev_s *chris_dev = container_of(inode->i_cdev, struct chris_dev_s, cdev);

	CHRIS_LOG(KLOG_DEBUG, "\n");

    priv_data = kzalloc(sizeof(struct chris_priv_data_s), GFP_KERNEL);
    RETURN_VAL_DO_INFO_IF_FAIL(priv_data, -ENOMEM,
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


struct file_operations chris_fops = {
	.owner =		THIS_MODULE,
	.open =		chris_open,
	.release =	chris_release,
};


static int chris_setup_cdev(struct chris_dev_s *dev, int major, int index)
{
    int ret, devno = MKDEV(major, index);

	CHRIS_LOG(KLOG_DEBUG, "major = %d\n", major);

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

    ret = alloc_chrdev_region(&devno, 0, CHRIS_DEVICE_NUM, "chris");
    RETURN_VAL_DO_INFO_IF_FAIL(!ret, ERR_PTR(ret), 
        CHRIS_LOG(KLOG_DEBUG, "alloc_chrdev_region failed! ret = %d\n", ret););

	CHRIS_LOG(KLOG_DEBUG, "devno = 0x%x\n", devno);

    chris_dev = kzalloc(sizeof(struct chris_dev_s) * CHRIS_DEVICE_NUM, GFP_KERNEL);
    DO_INFO_IF_EXPR_IS_ERR(chris_dev, 
        CHRIS_LOG(KLOG_DEBUG, "chris_dev kzalloc failed! \n"); ret = -ENOMEM; goto fail);


    for (i = 0; i < CHRIS_DEVICE_NUM; i++) {
        ret = chris_setup_cdev(chris_dev + i, MAJOR(devno), i);
        DO_INFO_IF_EXPR_UNLIKELY(!ret,
            CHRIS_LOG(KLOG_DEBUG, "chris_setup_cdev failed! \n"); goto fail);
    }

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


