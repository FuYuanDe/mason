#ifndef __MYHOOK_H__
#define __MYHOOK_H__

/* netlink protocol */
#define NETLINK_CAPTURE_MODULE              25

#define USER_MAX     20

/* netlink msg type */
typedef enum netlink_capture_type {
    CAPTURE_ADD = NLMSG_MIN_TYPE +1,        /* value : 17 */
    CAPTURE_DELETE,                         /* value : 18 */

    CAPTURE_END,
}NETLINK_CAPTURE_TYPE;

#ifndef CAPTURE_ALL
/* ip protocol */
#define CAPTURE_ALL   ((unsigned int)(~(0<<31)))
#define CAPTURE_TCP   ((unsigned int)(1<<0))
#define CAPTURE_UDP   ((unsigned int)(1<<1))
#define CAPTURE_ICMP  ((unsigned int)(1<<2))
#endif

#define LOG_INFO(fmt, arg...) printk("<3> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)
#define LOG_WARN(fmt, arg...) printk("<3> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)
#define LOG_ERR(fmt, arg...) printk("<3> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)

#define LOG_DEBUG(fmt, arg...) if(capture_debug) \
                              printk("<1> [capture] %s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)  

#define capture_write_lock(lock)      write_lock_bh(lock)
#define capture_write_unlock(lock)    write_unlock_bh(lock)
#define capture_read_lock(lock)       read_lock_bh(lock)
#define capture_read_unlock(lock)     read_unlock_bh(lock)


#ifndef CIP1
#define CIP1(addr)  ((unsigned char *)&addr)[0]
#define CIP2(addr)  ((unsigned char *)&addr)[1]
#define CIP3(addr)  ((unsigned char *)&addr)[2]
#define CIP4(addr)  ((unsigned char *)&addr)[3]
#endif

struct capture_timer {
    unsigned int taskid;
    struct timer_list timer;
};

struct capture_mtu {
    unsigned int taskid;
    unsigned int mtu;
};
union capture_inet_addr {
    unsigned int all[4];
    __be32 ip;
    __be32 ip6[4];
};

struct capture_addr {
    __be16 local_port;
    __be16 remote_port;
    union capture_inet_addr local_ip;
    union capture_inet_addr remote_ip;
};

struct capture_port_range {
    unsigned short min;
    unsigned short max;
};

/* ctl task */
struct capture_task {
    unsigned int taskid;                /* task id      */
    struct capture_task * task_next;    /* next task    */
};

/* ctl block */
struct capture_info {
    unsigned int taskid;
    unsigned int localflag;
    unsigned int protocol;
    struct capture_addr addr;
    union  capture_inet_addr saddr;
    union  capture_inet_addr daddr;
};

/* ctl unit */
struct capture_ctl {
    struct capture_info cache;
    struct capture_ctl *next_ctl;
};

/* mgr unit */
struct capture_mgr {
    struct capture_port_range ports;
    struct capture_mgr *next_mgr;
    struct capture_ctl *ctl;
};

/* mgr list head */
struct capture_mgr_root {
    rwlock_t lock;
    struct capture_task *task_list;
    struct capture_mgr *mgr;
};

/* filter */
struct capture_filter_nl {
    unsigned short min;         /* >=1     */
    unsigned short max;         /* <=65535 */
    unsigned int protocol;      
    union capture_inet_addr saddr;  /* could be 0 */    
    union capture_inet_addr daddr;  /* could be 0 */    
};

/* structure for netlink message */
struct capture_task_info_nl {
    unsigned int taskid;                /* task id                      */
    unsigned int localflag;             /* local server or rmote server */
    unsigned int timerval;              /* task timeval                 */
    struct capture_addr addr;           /* remote addr and local addr   */
    struct capture_filter_nl filter[1]; /* filter                       */ 
};


#endif
