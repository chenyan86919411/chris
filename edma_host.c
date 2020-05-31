#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/proc_fs.h>
//#include <linux/seg_file.h>

#include "chris.h"
#include "edma_host.h"

#define SEND2RECV
#define EDMA_TIMER

static struct edma_user_inft_s *g_user_func[TYPE_MAX] = {};
static struct proc_dir_entry *edma_proc_dir = NULL;
//static struct bma_dev_s *g_bma_dev = NULL;
/*
static int edma_host_dma_interrupt(struct edma_host_s *edma_host);

static int userinfo_proc_show(struct seg_file *seg, void *v)
{
	struct bma_user_s *user = NULL;
	
	seq_printf(seg, "userinfo: \n");
	if (g_bma_dev) {
        list_for_each_entry_rcu(user, &g_bma_dev->priv_list, link) {
            seq_printf(seg, "type: %d, subtype: %d, max: %d, cur: %d\n", 
                user->type, user->subtype, user->max_recvmsg_nums, user->cur_recvmsg_nums);
        }
	}
    return 0;
}


static int userinfo_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, userinfo_proc_show, NULL);
}

static const struct file_operations proc_userinfo_operations = 
{
    .open = userinfo_proc_open,
    .read = seq_read,
    .write = seq_write,
    .open = single_release,
}


static int debuglevel_proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    if(count) {
        char c;

        if(get_user(c, buf)) {
            return -EFAULT;
        }

        if((c >= '0') && (c <= '1')) {
            g_debug_level = c - '0';
        } else {
            return -EFAULT;
        }           
    }

    return count;
}

static int debuglevel_proc_show(struct seg_file *seg, void *v)
{
    seq_printf(seg, "%d\n", g_debuglevel);
}

static int debuglevel_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, debuglevel_proc_show, NULL);
}


static const struct file_operations proc_debuglevel_operations = 
{
    .open = debuglevel_proc_open,
    .read = seq_read,
    .write = debuglevel_proc_write,
    .llseek = seq_lseek,
    .open = single_release,
}

static int edma_host_proc_init(struct bma_dev_s *bma_dev)
{
    struct proc_dir_entry *p;
    int rc = -ENOMEM;

    edma_proc_dir = proc_mkdir("edma", bma_dev->proc_bma_root);
    if(!edma_proc_dir) {
        goto out;
    }

    p = proc_create("userinfo", S_IRUGO, parent,edma_proc_dir);
    if(!p) {
        goto out_userinfo;
    }

    p = proc_create("debuglevel", S_IWUGO | S_IRUGO, edma_proc_dir);
    if(!p) {
        goto out_debuglevel;
    }

    rc = 0;

out:
    return rc;

out_debuglevel:
    remove_proc_entry("userinfo", edma_proc_dir);

out_userinfo:
    remove_proc_entry("edma", bma_dev->proc_bma_root);
    goto out;
}

static void edma_host_proc_exit(struct bma_dev_s *bma_dev)
{
    remove_proc_entry("debuglevel", edma_proc_dir);
    remove_proc_entry("userinfo", edma_proc_dir);
    remove_proc_entry("edma", bma_dev->proc_bma_root);
}

static int is_edma_b2h_int(struct edma_host_s *edma_host)
{
    notify_msg *pnm = (notify_msg *)edma_host->edma_flag;

    if (IS_EDMA_B2H_INT(pnm->int_flag)) {
        CLEAR_EDMA_B2H_INT(pnm->int_flag);
        return 0;
    }
    return -1;
}

static void edma_host_to_bmc(struct edma_host_s *edma_host)
{
    unsigned int data;

    data = *(unsigned int)(char *)edma_host->hostrtc_viaddr + HOSTTRC_INT_OFFSET);
    data |= 0X00000001;
    *(unsigned int)(char *)edma_host->hostrtc_viaddr + HOSTTRC_INT_OFFSET) = data;
}

static void edma_host_int_to_bmc(struct edma_host_s *edma_host)
{
    notify_msg *pnm = (notify_msg *)edma_host->edma_flag;

    SET_EDMA_H2B_INT(edma_host->int_flag);
    edma_host_int_to_bmc(edma_host);
}

static int check_status_dmah2b(struct edma_host_s *edma_host)
{
    unsigned int data;
    struct pci_dev *pdev = edma_host->pdev;

    pci_read_config_dword(pdev, REG_PCIE1_DMAREAD_STATUS, &data);

    if (data & (1 << SHIFT_PCIE1_DMAREAD_STATUS)) {
        return 1; //ok
    } else {
        return 0; //busy
    }
}

static int check_status_dmab2h(struct edma_host_s *edma_host)
{
    unsigned int data;
    struct pci_dev *pdev = edma_host->pdev;

    pci_read_config_dword(pdev, REG_PCIE1_DMAWRITE_STATUS, &data);

    if (data & (1 << SHIFT_PCIE1_DMAWRITE_STATUS)) {
        return 1; //ok
    } else {
        return 0; //busy
    }
}

static int clear_int_dmah2b(struct edma_host_s *edma_host)
{
    unsigned int data;
    struct pci_dev *pdev = edma_host->pdev;

    pci_read_config_dword(pdev, REG_PCIE1_DMAREADINT_STATUS, &data);
    data |= (1 << SHIFT_PCIE1_DMAREADINT_STATUS);
    pci_write_config_dword(pdev, REG_PCIE1_DMAREADINT_STATUS, data);
}

static int clear_int_dmab2h(struct edma_host_s *edma_host)
{
    unsigned int data;
    struct pci_dev *pdev = edma_host->pdev;

    pci_read_config_dword(pdev, REG_PCIE1_DMAWRITEINT_STATUS, &data);
    data |= (1 << SHIFT_PCIE1_DMAWRITEINT_STATUS);
    pci_write_config_dword(pdev, REG_PCIE1_DMAWRITEINT_STATUS, data);
}

int edma_host_mmap(struct edma_host_s *edma_host, struct file* filp, struct vm_area_struct *vma) 
{
    unsigned long size = 0;
    unsigned long offs = 0;
    unsigned long phys = 0;
    int ret = 0;

    size = vma->vm_end - vma->vm_start;
    offs = vma->vm_pgoff; << PAGE_SHIFT;

    //MMAP通过offset来区分
    switch (offs & 0xfff0000) {
    case EDMA_MMA_H2B_DMABUF:
        if (size != EDMA_DMABUF_SIZE) {
            return -EINVAL;
        }

        phys = (unsigned long)edma_host->h2b_addr.dma_addr >> PAGE_SHIFT;
    break;
    case EDMA_MMA_B2H_DMABUF:
        if (size != EDMA_DMABUF_SIZE) {
            return -EINVAL;
        } 

        phys = (unsigned long)edma_host->b2h_addr.dma_addr >> PAGE_SHIFT;
    break;
    default:
        return -EINVAL;
    break;    
    }

    vma->vm_ops = NULL;
    vma->vm_flags |= VM_IO | VM_LOCKED | VM_DONTEXPAND | VM_DONTDUMP;
    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

    return remap_pfn_range(vma, vma->vm_start, phys, size, vma->vm_page_prot);
}

int edma_host_dma_start(struct edma_host_s *edma_host, struct bma_priv_data_s *priv) 
{
    struct bma_user_s *user = NULL;
    struct bma_dev_s *bma_dev = NULL;
    unsigned long flags;

    bma_dev = container_of(edma_host, struct bma_dev_s, edma_host);
    
    spin_lock_irqsave(&bma_dev->priv_list_lock, flags);    
    list_for_each_entry_rcu(user, &bma_dev->priv_list, link) {
        if (user->dma_transfer) {
            spin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);
            return -EBUSY;
        }
    }

    priv->user.dma_transfer = 1;
    spin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);

    return 0;
}

*/
static int edma_host_send_msg(struct edma_host_s *edma_host)
{/*
    struct edma_mbx_hdr_s *send_mbx_hdr = NULL;
    static unsigned int timer_cnt = 0;

    send_mbx_hdr = (struct edma_mbx_hdr_s *)edma_host->edma_send_addr;

    if (send_mbx_hdr->mbxlen > 0) {
        if (timer_cnt++ > 100) {
            send_mbx_hdr->mbxlen = 0;
        }

        if (timer_cnt++ > 5) {
#ifdef SEND2RECV
            edma_host_int_to_bmc(edma_host);
#else
            tasklet_hi_schedule(&edma_host->tasklet);
#endif
        }
        return -EFAULT;
    } else {    //只有0才确认msg已经被取走
        unsigned long flags;
        void *vaddr = (void *)edma_host->edma_send_addr + SIZE_OF_MBX_HDR;

        timer_cnt = 0;
        spin_lock_irqsave(&edma_host->send_msg_lock, flags);

        //没有msg要发送
        if (0 == edma_host->msg_send_write) {
            spin_unlock_irqrestore(&edma_host->send_msg_lock,flags);
            return 0;
        }
        memcpy(vaddr, edma_host->edma_send_buf, edma_host->msg_send_write);
        send_mbx_hdr->mbxlen = edma_host->msg_send_write;
        edma_host->msg_send_write = 0;

        spin_unlock_irqrestore(&edma_host->send_msg_lock,flags);

#ifdef SEND2RECV
        edma_host_int_to_bmc(edma_host);
#else
        tasklet_hi_schedule(&edma_host->tasklet);
#endif        
        return -EAGAIN; //保证定时器再进一次，其实没必要
    }*/
    return 0;
}



#ifdef EDMA_TIMER
static int edma_host_timeout(unsigned long data)
{
    int ret = 0;
    struct edma_host_s *edma_host = (struct edma_host_s *)data;

	CHRIS_LOG(KLOG_DEBUG, "edma_host_timeout\n");

    ret = edma_host_send_msg(edma_host);
    DO_INFO_IF_EXPR_LIKELY(ret < 0,
        mod_timer(&edma_host->timer, jiffies_64 + TIMER_INTERVAL_CHECK));
}
/*
static int edma_host_dma_timeout(unsigned long data)
{
    int ret = 0;
    struct edma_host_s *edma_host = (struct edma_host_s *)data;

    ret = edma_host_dma_interrupt(edma_host);
    DO_INFO_IF_EXPR_LIKELY(ret < 0,
        mod_timer(&edma_host->dmatimer, jiffies_64 + DMA_TIMER_INTERVAL_CHECK));
}*/
#else
static int edma_host_thread(void *arg)
{
    int timeout = 0;
    struct edma_host_s *edma_host = (struct edma_host_s *)arg;

	CHRIS_LOG(KLOG_DEBUG, "edma_host_thread start!\n");

    while(!kthread_should_stop()) {
		CHRIS_LOG(KLOG_DEBUG, "edma_host_thread 1\n");
        //timeout = wait_for_completion_interruptible(&edma_host->msg_ready);
        timeout = wait_for_completion_interruptible_timeout(&edma_host->msg_ready, 10000);
        
		CHRIS_LOG(KLOG_DEBUG, "edma_host_thread, timeout = %d\n", timeout);

        (void)edma_host_send_msg(edma_host);

        //(void)edma_host_dma_interrupt(edma_host);
    }

    return 0;
}
#endif
/*
int edma_host_copy_msg(struct edma_host_s *edma_host, void *msg, size_t msg_len)
{
    int ret = 0;
    unsigned long flags;

    spin_lock_irqsave(&edma_host->send_msg_lock, flags);

    if ((edma_host->msg_send_write + msg_len) <= (HOST_MAX_SEND_MBX_LEN - SIZE_OF_MBX_HDR)) {
        memcpy(edma_host->msg_send_buf + edma_host->msg_send_write, msg, msg_len);
        edma_host->msg_send_write += msg_len;
        
        spin_unlock_irqrestore(&edma_host->send_msg_lock,flags);
        
#ifdef EDMA_TIMER
        mod_timer(&edma_host->timer, jiffies_64);
#else
        completion(&edma_host->msg_ready);
#endif
    } else {
        ret = -ENOSPC;
        spin_unlock_irqrestore(&edma_host->send_msg_lock,flags);
    }

    return ret;
}

int edma_host_add_msg(struct edma_host_s *edma_host, struct bma_priv_data_s *priv, void *msg, size_t msg_len)
{
    int ret = 0;
    struct edma_msg_hdr_s *hdr = (struct edma_msg_hdr_s *)msg;
    struct edma_user_inft_s *user_inft = NULL;

    if (msg_len > (HOST_MAX_SEND_MBX_LEN - SIZE_OF_MBX_HDR)) {
        return -ENOSPC;
    }

    hdr->type = priv->user.type;
    hdr->subtype = priv->user.subtype;
    hdr->user_id = priv->user.user_id;
    
    user_inft = edma_host_get_user_inft(priv->user.type);
    RETURN_VAL_DO_INFO_IF_IS_ERR(user_inft, PTR_ERR(user_inft), 
        CHRIS_LOG(KLOG_ERROR, "edma_host_get_user_inft failed! err = %d\n", PTR_ERR(user_inft)););

    if (user_inft->add_msg) {
        int ret = 0;

        ret = user_inft->add_msg(msg, msg_len);
        RETURN_VAL_DO_INFO_IF_FAIL(!ret, ret, 
            CHRIS_LOG(KLOG_ERROR, "add_msg failed! err = %d\n", ret););
    } else {
        ret = edma_host_copy_msg(edma_host, msg, msg_len);
        RETURN_VAL_DO_INFO_IF_FAIL(!ret, ret, 
            CHRIS_LOG(KLOG_ERROR, "edma_host_copy_msg failed! err = %d\n", ret););
    }

    return ret;
}

int edma_host_recv_msg(struct edma_host_s *edma_host, struct emda_recv_msg_s **msg)
{
    unsigned long flags;
    struct list_head *entry = NULL;
    struct edma_recv_msg_s *msg_tmp = NULL;
    struct bma_dev_s *bma_dev = NULL;

    bma_dev = container_of(edma_host, struct bma_dev_s, edma_host);
    
    spin_lock_irqsave(&bma_dev->priv_list_lock,flags);
    //////////////////////////////////////有问题
    if (list_empty(&priv->recv_msgs)) {
        priv->user.cur_recvmsg_nums = 0;
        spin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);
        return -EAGAIN;     
    }

    entry = priv->recv_msg.next;
    msg_tmp = container_of(entry, struct edma_recv_msg_s, link);
    list_del(entry);

    if (priv->user.cur_recvmsg_nums > 0) {
        priv->user.cur_recvmsg_nums--;
    }

    spin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);

    *msg = msg_tmp;
    
    return 0;  
}

static int edma_host_insert_recv_msg(struct edma_host_s *edma_host, struct edma_msg_hdr_s *msg_header)
{
    unsigned long flags;
    struct bma_dev_s *bma_dev = NULL;
    struct bma_priv_data_s *priv = NULL;
    struct bma_user_s *user = NULL;
    struct bma_user_s usertmp = {};
    struct emda_recv_msg_s *recv_msg = NULL;

    bma_dev = container_of(edma_host, struct bma_dev_s, edma_host);
    
    recv_msg = kzalloc(sizeof(struct emda_recv_msg_s) + msg_header->datalen, GFP_KERNEL);
    RETURN_VAL_DO_INFO_IF_FAIL(recv_msg, -ENOMEM, 
        CHRIS_LOG(KLOG_ERROR, "recv_msg kzalloc sfailed! \n"););

    recv_msg->msg_len = msg_header->datalen;
    memcpy(recv_msg, msg_data, msg_header->data, msg_header->datalen);

    spin_lock_irqsave(&bma_dev->priv_list_lock,flags);
    list_for_each_entry_rcu(user, bma_dev->priv_list, link) {
        if ((user->type == msg_header->type) && 
            (user->subtype == msg_header->subtype)) {
            memcpy(&usertmp, user, sizeof(struct bma_user_s));

            if ((user->cur_recvmsg_nums >= user->max_recvmsg_nums) || 
                (user->cur_recvmsg_nums >= MAX_RECV_MSG_NUMS)) {
                spin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);

                kfree(recv_msg);
                return -EFAULT;
            }
            priv = container_of(user, struct bma_priv_data_s, user);
            list_add_tail(&recv_msg->link, priv->recv_list);
            user->cur_recvmsg_nums++;

            usertmp.cur_recvmsg_nums = user->cur_recvmsg_nums;
            pin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);

            return 0;
        }
    }
    spin_unlock_irqrestore(&bma_dev->priv_list_lock,flags);
    kfree(recv_msg);
    return -EFAULT;
}

static int edma_host_msg_process(struct edma_host_s *edma_host, struct edma_msg_hdr_s *msg_header)
{
    return -1;
}
*/
void edma_host_isr_tasklet(unsigned long data)
{/*
    int result = 0;
    U16 len = 0;
    U16 off = 0;
    U16 msg_cnt = 0;
    
    struct edma_mbx_hdr_s *recv_mbx_hdr = NULL;
    struct edma_host_s *edma_host = (truct edma_host_s *)data;
    struct bma_dev_s *bma_dev = NULL;
    struct edma_msg_hdr_s *msg_header = NULL;
    unsigned char *ptr = NULL;

    bma_dev = container_of(edma_host, struct bma_dev_s, edma_host);
    
    recv_mbx_hdr = (struct edma_mbx_hdr_s *)edma_host->edma_recv_addr;
    msg_header = (struct edma_msg_hdr_s *)(char *)edma_host->edma_recv_addr + SIZEOF_MBX_HDR + recv_mbx_hdr->mbxoff);

    //曾经用readl
    off = recv_mbx_hdr->mbxoff;
    len = recv_mbx_hdr->mbxlen - off;
    if (0 == len) {
        recv_mbx_hdr->mbxoff = 0;
        recv_mbx_hdr->mbxlen = 0;
    }

    while(recv_mbx_hdr->mbxlen - off) {
        if (len < (SIZE_OF_MSG_HDR + msg_header->datalen)) {
            recv_mbx_hdr->mbxoff = 0;
            recv_mbx_hdr->mbxlen = 0;
            break;
        }

        if (edma_host_msg_process(edma_host, msg_header) < 0) {
            result = edma_host_insert_recv_msg(edma_host, msg_header);
            DO_INFO_IF_EXPR_UNLIKELY(result < 0,
                CHRIS_LOG(KLOG_ERROR, "edma_host_insert_recv_msg failed! \n"););
        }

        len -= SIZE_OF_MSG_HDR + sg_header->datalen;
        off += SIZE_OF_MSG_HDR + sg_header->datalen;

        msg_cnt++;

        if (msg_cnt > 2) {
            recv_mbx_hdr->mbxoff = off;
            tasklet_hi_schedule(&edma_host->tasklet);
            break;
        }

        if (!len) {
            recv_mbx_hdr->mbxoff = 0;
            recv_mbx_hdr->mbxlen = 0;
            break;
        }  
    }*/
}
/*
static int edma_host_dma_interrupt(struct edma_host_s *edma_host)
{
    return -EAGAIN;
}*/

irqreturn_t edma_host_irq_handle(struct edma_host_s *edma_host)
{
    //edma_host_interrupt(edma_host);

    tasklet_hi_schedule(&edma_host->tasklet);

    return IRQ_HANDLED;
}

/*

static int edma_host_malloc_dma_buf(struct bma_dev_s *bma_dev)
{
    void *kvaddr = NULL;
    dma_addr_t dma_addr = 0;
    struct edma_host_s *edma_host = &bma_dev->edma_host;

    memset(&edma_host->h2b_addr, 0, sizeof(struct edma_dma_addr_s));
    memset(&edma_host->b2h_addr, 0, sizeof(struct edma_dma_addr_s));

    kvaddr = pci_alloc_consistent(edma_host->pdev, EDMA_DMABUF_SIZE, &dma_addr);
    if(NULL == kvaddr) {
        return -ENOMEM;
    }

    edma_host->h2b_addr.kvaddr = kvaddr;
    edma_host->h2b_addr.dma_addr = dma_addr;
    edma_host->h2b_addr.len = EDMA_DMABUF_SIZE;
    
    kvaddr = pci_alloc_consistent(edma_host->pdev, EDMA_DMABUF_SIZE, &dma_addr);
    if(NULL == kvaddr) {
        return -ENOMEM;
    }

    edma_host->b2h_addr.kvaddr = kvaddr;
    edma_host->b2h_addr.dma_addr = dma_addr;
    edma_host->b2h_addr.len = EDMA_DMABUF_SIZE;

    return 0;
}



static void edma_host_free_dma_buf(struct bma_dev_s *bma_dev)
{
    struct edma_host_s *edma_host = &bma_dev->edma_host;

    if (edma_host->h2b_addr.kvaddr) {
        pci_free_consistent(edma_host->pdev, 
            edma_host->h2b_addr.len,
            edma_host->h2b_addr.kvaddr,
            edma_host->h2b_addr.dma_addr);

        edma_host->h2b_addr.kvaddr = NULL;
        edma_host->h2b_addr.dma_addr = 0;
        edma_host->h2b_addr.len = 0;
    }

    if (edma_host->b2h_addr.kvaddr) {
        pci_free_consistent(edma_host->pdev, 
            edma_host->b2h_addr.len,
            edma_host->b2h_addr.kvaddr,
            edma_host->b2h_addr.dma_addr);

        edma_host->b2h_addr.kvaddr = NULL;
        edma_host->b2h_addr.dma_addr = 0;
        edma_host->b2h_addr.len = 0;
    }
}

struct edma_user_inft_s *edma_host_get_user_inft(U32 type)
{
    if(unlikely(type >= TYPE_MAX)) {
        return ERR_PTR(-EINVAL);
    }
    
    return g_user_func[type];
}

int edma_host_user_register(U32 type, struct edma_user_inft_s *inft)
{
    if(unlikely(type >= TYPE_MAX) || unlikely(NULL == inft)) {
        return ERR_PTR(-EINVAL);
    }

    g_user_func[type] = inft;
    return 0;
}

int edma_host_user_unregister(U32 type)
{
    if(unlikely(type >= TYPE_MAX)) {
        return ERR_PTR(-EINVAL);
    }

    g_user_func[type] = NULL;
    return 0;
}
*/
int edma_host_init(struct edma_host_s *edma_host)
{
    int ret = 0;
    struct chris_descriptor_s *desc = NULL;

    desc = container_of(edma_host, struct chris_descriptor_s, host);
    //g_bma_dev = bma_dev;

    //ret = edma_host_proc_init(bma_dev);
    //RETURN_VAL_DO_INFO_IF_FAIL(!ret, ret,
    //    CHRIS_LOG(KLOG_ERROR, "edma_proc_init failed! \n"););

#ifdef EDMA_TIMER
    setup_timer(&edma_host->timer, edma_host_timeout, (unsigned long)edma_host);
    mod_timer(&edma_host->timer, jiffies_64 + TIMER_INTERVAL_CHECK);
    //setup_timer(&edma_host->dmatimer, edma_host_dma_timeout, (unsigned long)edma_host);
    //mod_timer(&edma_host->dmatimer, jiffies_64 + DMA_TIMER_INTERVAL_CHECK);
#else
    init_completion(&edma_host->msg_ready);
    edma_host->edma_thread = kthread_run(edma_host_thread, (void *)edma_host, "edma_host");
    if(IS_ERR(edma_host->edma_thread)) {
        return PTR_ERR(edma_host->edma_thread);
    }        
#endif

    edma_host->msg_send_buf = (unsigned char *)kzalloc(HOST_MAX_SEND_MBX_LEN, GFP_KERNEL);
    RETURN_VAL_DO_INFO_IF_FAIL(edma_host->msg_send_buf, -ENOMEM,
        CHRIS_LOG(KLOG_ERROR, "msg_send_buf kzalloc failed! \n"););

    edma_host->msg_aend_write = 0;
    spin_lock_init(&edma_host->send_msg_lock);

    tasklet_init(&edma_host->tasklet, edma_host_isr_tasklet, (unsigned long)edma_host);

    //edma_host->edma_flag = bma_dev->bma_pci_dev->edma_swap_addr;
    //edma_host->edma_send_addr = bma_dev->bma_pci_dev->edma_swap_addr + HOST_DMA_FLAG_LEN;
    //memset(edma_host->edma_send_addr, 0, SIZEOF_MBX_HDR);

#ifdef SEND2RECV
    edma_host->edma_recv_addr = edma_host->edma_send_addr;
#else
    edma_host->edma_recv_addr = edma_host->edma_send_addr + HOST_MAX_SEND_MBX_LEN;
#endif

    //(void)edma_host_malloc_dma_buf(bma_dev);

    //init_waitqueue_head(&edma_host->wq_dmah2b);
    //init_waitqueue_head(&edma_host->wq_dmab2h);

    
    //spin_lock_init(&edma_host->reg_lock);

    //edma_host->h2bstate = H2BSTATE_IDIE;
    //edma_host->b2hstate = B2HSTATE_IDIE;

    return 0;
}


void edma_host_cleanup(struct edma_host_s *edma_host)
{
    struct chris_descriptor_s *desc = container_of(edma_host, struct chris_descriptor_s, host);

    tasklet_kill(&edma_host->tasklet);
    if(edma_host->msg_send_buf) {
        kfree(edma_host->msg_send_buf);
        edma_host->msg_send_buf = NULL;
    }      

#ifdef EDMA_TIMER
    del_timer(&edma_host->timer);
    //del_timer(&edma_host->dmatimer);
#else
    complete(&edma_host->msg_ready); 
    kthread_stop(edma_host->edma_thread);  
#endif 
    
    //edma_host_free_dma_buf(bma_dev);
    //edma_host_proc_exit(bma_dev);
}

