
#ifndef _DEV_H
#define _DEV_H

#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/ioctl.h>
#include <linux/interrupt.h>

#include "chris.h"


struct chris_priv_data_s {
    struct list_head link;

	struct chris_dev_s *chris_dev;
};

struct chris_dev_s {
    struct list_head head;

	struct fasync_struct *async_queue;
	struct tasklet_struct tasklet;
	wait_queue_head_t wait; 

    struct cdev cdev;
};

extern struct chris_dev_s *dev_init(void);
extern void dev_cleanup(struct chris_dev_s *chris_dev);

#endif // _DEV_H


