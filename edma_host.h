
#ifndef _EDMA_HOST_H
#define _EDMA_HOST_H

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/timer.h>


#define TYPE_MAX 3

struct edma_mbx_hdr_s {
    u16 mbxlen;
    u16 mbxoff;
};
    
struct edma_msg_hdr_s {
    int datalen;
};

struct bma_priv_data_s {

};

struct bma_user_s {
    int type;
    int subtype;
};

struct edma_user_inft_s {
};

struct edma_dma_addr_s {
};

struct emda_recv_msg_s {
};

struct edma_host_s {

	//for send
	struct timer_list timer;
		
	struct completion msg_ready;
	struct task_struct *edma_thread;
	
	
	unsigned char *msg_send_buf;
	spinlock_t send_msg_lock;

	struct tasklet_struct tasklet;

	//swap buf
	unsigned char *edma_recv_addr;	
	unsigned char *edma_send_addr;
	
	
	int msg_aend_write;
};

struct bma_dev_s {
};

#define TIMER_INTERVAL_CHECK 10000
#define DMA_TIMER_INTERVAL_CHECK

#define HOST_MAX_SEND_MBX_LEN	4096


#define HOST_DMA_FLAG_LEN
#define SIZE_OF_MBX_HDR
#define SIZE_OF_MSG_HDR

int edma_host_init(struct edma_host_s *edma_host);
void edma_host_cleanup(struct edma_host_s *edma_host);


#endif // _EDMA_HOST_H


