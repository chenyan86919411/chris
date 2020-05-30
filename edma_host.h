
struct edma_mbx_hdr_s {
    U16 mbxlen;
    U16 mbxoff;
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
};

struct bma_dev_s {
};

#define TIMER_INTERVAL_CHECK
#define DMA_TIMER_INTERVAL_CHECK

#define HOST_MAX_SEND_MBX_LEN


#define HOST_DMA_FLAG_LEN
#define SIZE_OF_MBX_HDR
#define SIZE_OF_MSG_HDR


