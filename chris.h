
#ifndef _CHRIS_H
#define _CHRIS_H

#include <linux/slab.h>
#include "edma_host.h"


#define CHRIS_DEVICE_NUM 2

enum {
    KLOG_DEBUG = 0,
    KLOG_ERROR = 1,
};


extern int debug_level;
#define CHRIS_LOG(level, fmt, args...) do {\
    if (level >= debug_level) { \
        printk(KERN_ALERT "Chris: %s(), %s, %d, " fmt, __func__, __FILE__, __LINE__, ##args);\
    }\
}while(0)


//expr 不成立，则执行info，返回val，用于错误码判断
#define RETURN_VAL_DO_INFO_IF_FAIL(expr, val, info) do {\
    if (unlikely(!(expr))) { \
        info;\
        return val;\
    }\
}while(0)

//expr 不成立，则执行info，返回，用于错误码判断
#define RETURN_DO_INFO_IF_FAIL(expr, info) do {\
    if (unlikely(!(expr))) { \
        info;\
        return;\
    }\
}while(0)

//expr 很可能成立，则执行info，用于错误码判断
#define DO_INFO_IF_EXPR_LIKELY(expr, info) do {\
    if (likely(!(expr))) { \
        info;\
    }\
}while(0)

//expr 不可能成立，则执行info，用于错误码判断
#define DO_INFO_IF_EXPR_UNLIKELY(expr, info) do {\
    if (unlikely(!(expr))) { \
        info;\
    }\
}while(0)

//IS_ERR(expr)成立，则执行info，返回val，用于地址判断
#define RETURN_VAL_DO_INFO_IF_IS_ERR(expr, val, info) do {\
    if (IS_ERR(expr)) { \
        info;\
        return val;\
    }\
}while(0)

//IS_ERR(expr) 成立，则执行info，用于地址判断
#define DO_INFO_IF_EXPR_IS_ERR(expr, info) do {\
    if (IS_ERR(expr)) { \
        info;\
    }\
}while(0)


struct chris_descriptor_s {
	struct edma_host_s host;
    struct chris_dev_s *chris_dev;
};


#endif // _CHRIS_Hs


