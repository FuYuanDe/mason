/*
 *	Linux NET3:	xrtp relay decoder header.
 *
 *	Authors: Kyle <zx_feng807@foxmail.com>
 *
 */
 
#ifndef __XRTP_RELAY_H__
#define __XRTP_RELAY_H__

//#define RTP_PACKET_TIME_DELAY       1

#define RTP_LOCK_SPINLOCK           1

#define RTP_TBL_SIZE                65536           /* �����ṹ */
#define NETLINK_XRTP_RELAY_MODULE   23    /* netlinkͨ�Žӿ�id */

#define RTP_INADDR_LOOPBACK         0x100007f  /* in_aton("127.0.0.1") */

#define RTP_CAPTRUE_MAX             512

#define LOG_INFO(fmt, arg...)   printk("<6>%s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)
#define log_debug(fmt,arg...)   if(g_rtp_log_enable) \
    printk("<6>%s:%d "fmt, __FUNCTION__ , __LINE__, ##arg)
#define hook_info(fmt, arg...)	printk("<3>%s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)

#define hook_debug(fmt, arg...) if (g_rtp_log_enable) \
    printk("<3>%s:%d " fmt, __FUNCTION__ , __LINE__, ##arg)


#ifdef RTP_LOCK_SPINLOCK
#define rtp_write_lock(lock)       spin_lock_bh(lock)
#define rtp_write_unlock(lock)     spin_unlock_bh(lock)
#define rtp_read_lock(lock)        spin_lock_bh(lock)
#define rtp_read_unlock(lock)      spin_unlock_bh(lock)
#else
#define rtp_write_lock(lock)       write_lock_bh(lock)
#define rtp_write_unlock(lock)     write_unlock_bh(lock)
#define rtp_read_lock(lock)        read_lock_bh(lock)
#define rtp_read_unlock(lock)      read_unlock_bh(lock)
#endif


#ifndef NIPQUAD
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]
#endif
#ifndef NIP1
#define NIP1(addr)  ((unsigned char *)&addr)[0]
#define NIP2(addr)  ((unsigned char *)&addr)[1]
#define NIP3(addr)  ((unsigned char *)&addr)[2]
#define NIP4(addr)  ((unsigned char *)&addr)[3]
#endif
#ifndef NMACQUAD
#define NMACQUAD(mac)  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
#endif

#ifndef US_TO_NS
#define US_TO_NS(usec)		((usec) * 1000)
#define MS_TO_US(msec)		((msec) * 1000)
#define MS_TO_NS(msec)		((msec) * 1000 * 1000)
#endif

#define DDOS_DSCP_MASK    0xfc    /* 11111100 */
#define DDOS_DSCP_SHIFT   2
#define DDOS_DSCP_MAX     0x3f    /* 00111111 */


typedef enum rtp_netlink_type {    
    RTP_MEDIA_TBL_CREATE = NLMSG_MIN_TYPE + 1,      /* value:17 */
    RTP_MEDIA_TBL_DELETE,                           /* value:18 */
    RTP_MEDIA_TBL_SETCFG,                           /* value:19 */
    RTP_MEDIA_TBL_UPDATE,                           /* value:20 */
    RTP_MEDIA_TBL_DELALL,                           /* value:21 */
    RTP_MEDIA_TBL_SETCPU,                           /* value:22 */
    RTP_MEDIA_TBL_SET_SLOT_ID,                      /* value:23 */
    RTP_MEDIA_TBL_DEBUG,
    RTP_MEDIA_TBL_CAPTURE_START = NLMSG_MIN_TYPE + 10, /* value:26 */
    RTP_MEDIA_TBL_CAPTURE_STOP,                     /* value:27 */
    
    RTP_MEDIA_TBL_DEBUG_ENABLE = NLMSG_MIN_TYPE + 13,   /* value 29 */
    RTP_MEDIA_TBL_DEBUG_DISABLE,                          /* value 30 */   
    RTP_MEDIA_TBL_RFC2833_REPORT,                       /* value 31 */

    RTP_MEDIA_TBL_NOTIFY = 100,
    RTP_MEDIA_TBL_UNNOTIFY = 101,
    RTP_MEDIA_TBL_END,
} RTP_NETLINK_TYPE;

typedef enum rtp_report_type {
    RTP_MSG_TYPE_STATIS = 1,
    RTP_MSG_TYPE_END,
} RTP_MSG_TYPE;

typedef enum rtp_ioctl_type {
    RTP_IOC_READ_STATIS = 1,
    RTP_IOC_END,
} RTP_IOCTL_TYPE;

struct rtp_port_range {
    unsigned int port_min;
	unsigned int port_max;
};

struct rtp_dispatch_cpu {
    unsigned int cpu_base;
    unsigned int cpu_nums;
};

struct rtp_capture_media {
    unsigned int port;
    unsigned char ip_type;
    unsigned char ip[16];
};

/* Internet address. */
struct rtp_in_addr {
	__be32	s_addr;
};

struct rtp_in6_addr {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
};

union rtp_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
	struct rtp_in_addr	in;
	struct rtp_in6_addr	in6;
};

struct rtcp_statis {
    unsigned int sender_pkts;           /* �����߷���rtp���ݰ����� */
    unsigned int fraction_lost;         /* ��ʧ�� */
    unsigned int lost_pkts;             /* �ۼư���ʧ��Ŀ */
    unsigned int jitter;                /* ���ܶ��� */
};

struct rtp_statis {
    unsigned int        recvpkts;                   /* ���հ��� */
    unsigned int        recvbytes;                  /* �����ֽ��� */
    unsigned int        recvrate;
    unsigned int        recvrate_rtime;
    unsigned int        recvpkts_err;
    unsigned int        recvbytes_err;

    unsigned int        todspkts;
    unsigned int        todspbytes;
    
    unsigned int        fromdspkts;
    unsigned int        fromdspbytes;
    unsigned int        fromdsp_rate;
    unsigned int        fromdsp_rate_rtime;

    unsigned int        sendpkts_err;
    unsigned int        sendbytes_err;
    
    struct rtcp_statis  rtcp;
};

struct rtp_info {
    unsigned char encode_name[RM_NAME_MAX_LEN]; /* ��������֣�������ʶ��̬���룬����iLBC */
    unsigned char param[RM_NAME_MAX_LEN];       /* �ñ�����Ӧ��һЩ����,�������729��annexb=no */
    unsigned short int payload;                 /* �����:0,8,18,4,98 */
    unsigned char slience_supp;                 /* �������ƿ��أ�true���򿪾������� */
    unsigned char dtmf_detect;                  /* DTMF detect���� */   
    unsigned int  dtmf_action;                  /* DTMF detect���� */
    unsigned int bitrate;                       /* ������ */
    unsigned int max_psize;                     /* ��������ݰ����� */
    unsigned int rfc2833;
    unsigned int max_ptime;                     /* ���ʱ�� */
    unsigned int rfc2833_remote;                /* Զ��rfc2833 */
    unsigned int srtp;                          /* �Ƿ�srtp���� */
};

struct rtp_qos_pkts {
    /* rtp conn flow qos */
    int pkts_power;                     /* 1������ͨ���İ��� */
    int pkts_rtime;                     /* ��λʱ�����Ѿ�ͨ�����ٰ� */
    unsigned long last_update_time;     /* ����������ʱ�� */
};

#define KERNEL_ONLY_USE_ORIG_FOR_SEND          (1 << 0)

struct rtp_media {
    unsigned char       ip_type;
    __be16              local_port;                 /* ���ض˿ں� */
    unsigned char       local_mac[ETH_ALEN];        /* ����mac��ַ */
    union rtp_inet_addr local_ip;                   /* ����ip��ַ */

    /*���޸ĵĶԶ˷��͸������豸��rtp�����еĵ�ַ��Ϣ����Ϊ�п��ܳ���һ�����
      Э�̳����ĶԶ˵�ַ�Ͷ˿���ʵ�ʷ��͹����Ĳ�һ�£���ȴҪ�󱾶�
      ���͹�ȥ��ʱ������Ҫʹ��ԭ����ip�Ͷ˿���Ϣ*/
    __be16              remote_port; 
    unsigned char       remote_mac[ETH_ALEN];       /* �Զ�mac��ַ */
    union rtp_inet_addr remote_ip;

    /*ԭʼ�ı����豸���͸��Զ�rtp������ʹ�õĵ�ַ��Ϣ�������޸�*/
    __be16              orig_remote_port; 
    unsigned char       orig_remote_mac[ETH_ALEN];       /* �Զ�mac��ַ */
    union rtp_inet_addr orig_remote_ip;

    __be32              flag;

    struct net_device	*dev;
    struct rtp_statis   statis;
    
    struct rtp_media    *ref_conn;                  /* ƥ�������ʱ��ʹ��fw_conn������Ϣת�� */

    unsigned int        media_lock;                 /* ý��˨ */
    unsigned int        media_lock_param;
    unsigned int        media_lock_status_ptks;     /* ý��˨״̬��������ǰ����ͨ�������� */
    unsigned int        media_sync_flag;            /* ����ͺ�������ͬһ�߼��ӿ��µ�ý��˨��Ϣ */
    unsigned int        media_lock_ssrc;

    unsigned int        media_type;
    union {
        struct rtp_info rtp;                        /* media_type Ϊaudio��Ч */
    } media_data;

    /* dspת����ز��� */
    int	                chan_id;                    /* DSP channel�� */
    struct net_device	*dev_dsp;                   /* rtp to dsp ת���Ľӿ� */

    /* qos */
    __u8    dscp;
    /* vlan */
    __u16   vlanid;

    /* rtp �����հ��������� */
    struct rtp_qos_pkts  qos_pkts;

    #ifdef RTP_PACKET_TIME_DELAY
    unsigned long last_rx;
    unsigned int delay_min;
    unsigned int delay_max;
    unsigned int delay_total;
    unsigned int delay_2ms_pkts;
    unsigned int delay_8ms_pkts;
    unsigned int last_pktin_times;
    unsigned int delay_pktin_min;
    unsigned int delay_pktin_max;
    unsigned int delay_pktin_total;
    unsigned int delay_pktin;
    #endif
    
};

struct rtp_relay_cache {
    unsigned long       create_time;
    struct rtp_media    aconn;
    struct rtp_media    bconn;
};

struct rtp_ctrl_tbl {
    #ifdef RTP_LOCK_SPINLOCK
    spinlock_t lock;
    #else
    rwlock_t lock;
    #endif
    unsigned char captrue_flag;
    struct rtp_relay_cache *cache;
};

/* copy from rtp_relay.h(james) */
typedef struct tag_DSP_SOCK_DATA
{
	__u16	usLength;
	__u16	usChan;
	__u16	usType;
	__u16	usMagic;
	__u32	ulReserved;
} ST_DSP_SOCK_DATA;

struct rtp_dsp_entry {
    __u16   dir;        /* original or reply */
    __u16   connid;  
};

struct rm_medai_report {
    unsigned int conn_id;
    unsigned int msg_type;

    union {
        struct {
            unsigned long live_times;
            struct rtp_statis astat;
            struct rtp_statis bstat;
        } statis;
    
    } udata;
};

/* copy from xflow_ddos */
struct ddos_report {
    unsigned int ip_type;

    union {
        struct in_addr in;
        struct in6_addr in6;
    } u_ipaddr;
    unsigned int port;
    
    unsigned int msg_type;         /* ֪ͨ/�澯/���� */
    
    unsigned int recv_pkts;        /* TX������ */
    unsigned int recv_bytes;       /* TX�ֽ��� */
    unsigned int recv_rate; 
    unsigned int start_time;

    int           ifindex;
    unsigned char iface[32];
};

struct rfc2833hdr {
    __u8    event_id;
    __u8    flag;
    __u16   event_duration;
};

struct rfc2833_report {
    struct rfc2833hdr rfc2833;     /* rfc2833 �������� */
    unsigned short sport;          /* ��Դ�˿�     */
    unsigned short dport;          /* Ŀ�Ķ˿� */
    union {
        struct in_addr in;
        struct in6_addr in6;
    }u_saddr;                       /* ��Դip��ַ */
    union {
        struct in_addr in;
        struct in6_addr in6;
    }u_daddr;                       /* Ŀ��ip��ַ*/
};
#endif

