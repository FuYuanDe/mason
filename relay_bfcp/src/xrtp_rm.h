/*
 *	Linux NET3:	xrtp resource managent header
 *
 *	Authors: Kyle <zx_feng807@foxmail.com>
 *
 */

#ifndef __XRTP_RM_H__
#define __XRTP_RM_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/types.h>

#define RTP_RELAY_VERSION_2     1

#define RM_ETH_ALEN             6
#define RM_MEDIA_AUDIO          1   /* 语音:audio */
#define RM_MEDIA_VIDEO          2   /* media type:video */
#define RM_MEDIA_IMAGE          3   /* media type:image */
#define RM_MEDIA_APPLICATION    4   /* bfcp media */


#define RM_NAME_MAX_LEN         32
#define RM_LONG_NAME_MAX_LEN    64
#define RM_MEDIA_MAX_PORT       65535

#define RM_SIOCGSTAT            0x6b01

/* Internet address. */
struct rm_in_addr {
	__be32	s_addr;
};

struct rm_in6_addr {
	union {
		__u8		u6_addr8[16];
		__be16		u6_addr16[8];
		__be32		u6_addr32[4];
	} in6_u;
#define s6_addr			in6_u.u6_addr8
#define s6_addr16		in6_u.u6_addr16
#define s6_addr32		in6_u.u6_addr32
};

union rm_inet_addr {
	__u32		all[4];
	__be32		ip;
	__be32		ip6[4];
	struct rm_in_addr	in;
	struct rm_in6_addr	in6;
};

struct rm_crypto {
    unsigned char crypto[RM_NAME_MAX_LEN];      /* 加密算法名称 */
    unsigned char key[RM_LONG_NAME_MAX_LEN];    /* 加密key值 */
};

struct rm_init_cfg {
    unsigned int port_min;
	unsigned int port_max;
};

struct rm_delete_conn {
    unsigned int connid;                        /* 删除连接id           */
    unsigned int protocol;                      /* 指定删除协议类型 */
};

struct rm_rtp_info {
    unsigned char encode_name[RM_NAME_MAX_LEN]; /* 编解码名字，可用于识别动态编码，比如iLBC */
    unsigned char param[RM_NAME_MAX_LEN];       /* 该编解码对应的一些参数,比如对于729，annexb=no */
    unsigned short int payload;                 /* 编解码:0,8,18,4,98 */
    unsigned char slience_supp;                 /* 静音抑制开关，true，打开静音抑制 */
    unsigned char dtmf_detect;                  /* DTMF detect开关 */   
    unsigned int  dtmf_action;                  /* DTMF detect动作 */
    unsigned int bitrate;                       /* 比特率 */
    unsigned int max_psize;                     /* 最大打包报文长 */
    unsigned int rfc2833;
    unsigned int max_ptime;                     /* 最大打包时长 */
    unsigned int rfc2833_local;                 /* 本端rfc2833值 */
    //unsigned int srtp;                          /* SRTP连接标志 */
};

#define USER_ONLY_USE_ORIG_FOR_SEND          (1 << 7)

#define IP_TYPE_BIT_MASK            (0x7)

struct rm_media_conn {
    
    __u16 local_port;                           /* 本地端口号 */
    unsigned char local_mac[RM_ETH_ALEN];       /* 本端mac地址 */
    union rm_inet_addr local_ip;                /* 本端ip地址 */
    
    __u16 remote_port; 
    unsigned char remote_mac[RM_ETH_ALEN];      /* 对端mac地址 */
    union rm_inet_addr remote_ip;               /* 对端IP地址 */
                            /* 对端端口号1 */

    struct rm_crypto crypto;                    /* 加密信息 */

    __u16 vlanid;                               /* vlan id */
    __u16 dscp;                                 /* dscp值 */
	unsigned char protocol;
	unsigned char remotelock;
    unsigned char ip_type;                      /* ipv4 or ipv6 低3bit用作ip类型，其他bit用作其他用途*/
    char media_type;                            /* audio:1 /video:2 /image:3 中其中一种 */
    union {
        struct rm_rtp_info rtp;                 /* media_type 为audio有效 */
    } media_data;
    
    int chan_id;                                /* chan ID */
    int media_lock_param;                       /* 媒体栓锁定报文个数 */
};

struct rm_media_tbl {
    unsigned int conn_id;                       /* 最前面，连接id，目前等于端口号 */

    struct rm_media_conn aconn;                 /* original 方向连接信息 */
    struct rm_media_conn bconn;                 /* replay 方向连接信息 */
};

struct rm_rtcp_statis {
    unsigned int sender_pkts;           /* 发送者发送rtp数据包总数 */
    unsigned int fraction_lost;         /* 丢失率 */
    unsigned int lost_pkts;             /* 累计包丢失数目 */
    unsigned int jitter;                /* 接受抖动 */
};

struct rm_conn_statis {
    unsigned int       recvpkts;                   /* 接收包数 */
    unsigned int       recvbytes;                  /* 接收字节数 */
    unsigned int       recvrate;
    unsigned int       recvpkts_err;
    unsigned int       recvbytes_err;
    
    unsigned int       sendpkts;
    unsigned int       sendbytes;
    unsigned int       sendrate;
    
    struct rm_rtcp_statis rtcp;
};

struct rm_media_statis {
    unsigned int conn_id;

    struct rm_conn_statis astat;
    struct rm_conn_statis bstat;
};


#ifdef __cplusplus
}
#endif

#endif

