

#include "chris.h"
#include "dev.h"

#define CHRIS_VERSION "V1.0.0"
int debug_level = 0;

struct chris_descriptor_s *gcdesc = NULL;


static int __init chris_init(void)
{
    int ret = 0;
    struct chris_descriptor_s *cdesc = NULL;
    struct chris_dev_s *chris_dev = NULL;

    CHRIS_LOG(KLOG_DEBUG, "chris_init, version is %s\n", CHRIS_VERSION);

    cdesc = kzalloc(sizeof(struct chris_descriptor_s), GFP_KERNEL);
    RETURN_VAL_DO_INFO_IF_FAIL(cdesc, -ENOMEM,
        CHRIS_LOG(KLOG_DEBUG, "cdesc kzalloc failed!\n"););

    chris_dev = dev_init();
    DO_INFO_IF_EXPR_IS_ERR(chris_dev,
        CHRIS_LOG(KLOG_DEBUG, "dev_init failed!\n"); ret = PTR_ERR(chris_dev); goto fail;);

    cdesc->chris_dev = chris_dev;

    gcdesc = cdesc;
    return 0;
    
fail:
    dev_cleanup(chris_dev);
    return ret;
    
}


static int __exit chris_exit(void)
{
    if(gcdesc) {
       struct chris_dev_s *chris_dev = gcdesc->chris_dev;

       gcdesc->chris_dev = NULL;
       dev_cleanup(chris_dev);
    }   

	CHRIS_LOG(KLOG_DEBUG, "chris_exit\n");

	return 0;
}

module_init(chris_init);
module_exit(chris_exit);


