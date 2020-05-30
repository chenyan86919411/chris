
#ifndef _DEV_H
#define _DEV_H

#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/fs.h>


struct chris_priv_data_s {
    struct list_head link;
};

struct chris_dev_s {
    struct list_head head;
    struct cdev cdev;
};

extern struct chris_dev_s *dev_init(void);
extern void dev_cleanup(struct chris_dev_s *chris_dev);

#endif // _DEV_H


