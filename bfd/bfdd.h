#ifndef _BFDD_H
#define _BFDD_H
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <pthread.h>
#include <sys/uio.h>    
#include <stdint.h>     
#include <malloc.h>
#include <unistd.h>     
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>


/* 
   The Mandatory Section of a BFD Control packet has the following
   format:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                       My Discriminator                        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Your Discriminator                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Desired Min TX Interval                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Required Min RX Interval                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Required Min Echo RX Interval                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
// bfd首部格式
#pragma pack(push,1) 
struct bfdhdr
{
	uint8_t diag:5;            // 诊断码
	uint8_t version:3;         // 版本

	uint8_t mpoint:1;          // 保留字段
	uint8_t demand:1;          // 查询模式
	uint8_t auth:1;            // 认证字段
	uint8_t cplane:1;          // 控制平面
	uint8_t final:1;           // 终止标志位
	uint8_t poll:1;            // 起始标志位
	uint8_t sta:2;             // 状态码 

	uint8_t detect_mult;       // 检测次数
	uint8_t len;               // 报文长度

    uint32_t my_disc;            // 本端描述符
	uint32_t your_disc;          // 远端描述符
	uint32_t des_min_tx_intv;    // 期待发送时间
	uint32_t req_min_rx_intv;    // 期待接收时间
	uint32_t req_min_echo_rx_intv; // 期待echo报文时间

};
#pragma pack(pop)

#define BUFF_SIZE 512
/* BFD版本 */
#define BFD_VERSION 1

/* BFD长度*/
#define    BFD_CTRL_LEN          24
#define    BFD_CTRL_AUTH_LEN     26

/* BFD状态 */
#define BFD_STA_ADMINDOWN       0
#define BFD_STA_DOWN            1
#define BFD_STA_INIT            2
#define BFD_STA_UP              3
#define BFD_STA_MAX             4

/*   诊断码
 *   0 -- No Diagnostic 
 *   1 -- Control Detection Time Expired
 *   2 -- Echo Function Failed
 *   3 -- Neighbor Signaled Session Down
 *   4 -- Forwarding Plane Reset
 *   5 -- Path Down
 *   6 -- Concatenated Path Down
 *   7 -- Administratively Down
 *   8 -- Reverse Concatenated Path Down
 *   9-31 -- Reserved for future use
 */

#define    BFD_DIAG_NO_DIAG                     0
#define    BFD_DIAG_CTRL_TIME_EXPIRED           1       
#define    BFD_DIAG_ECHO_FAILED                 2
#define    BFD_DIAG_NBR_SESSION_DOWN            3
#define    BFD_DIAG_FWD_PLANE_RST               4
#define    BFD_DIAG_PATH_DOWN                   5
#define    BFD_DIAG_CONCATENATED_PATH_DOWN      6
#define    BFD_DIAG_ADMIN_DOWN                  7
#define    BFD_DIAG_REV_CONCATENATED_PATH_DOWN  8

#define BFD_DEFAULT_TX_INTERVAL 1000000         /* 1s, 默认接收间隔 */
#define BFD_DEFAULT_RX_INTERVAL 1000000         /* 1s, 默认发送间隔 */
#define BFD_DEFAULT_ECHO_RX_INTERVAL 0          /* 默认echo报文接收间隔 */
#define BFD_DEFAULT_DETECT_MULT 5               /* 默认检测倍数 */

//消息事件类型
#define MSG_EVENT_TX_TIMER    0   //发送事件
#define MSG_EVENT_RX_TIMER    1   //超时事件
#define MSG_EVENT_SOCKET      2   //接收事件
#define MSG_EVENT_DELETE      3   //删除事件
#define MSG_EVENT_START       4   //状态机初始事件


//epoll回调数据接口
struct epoll_callback_data {
	struct session *bfd_session;   //会话控制块指针
	int fd_type;            //文件描述符类型, 0:tx_timer, 1:rx_timer, 2:sockfd
	int fd;                 //文件描述符
};


// bfd会话表
struct session {
    struct session *neigh_next;     // 地址 hash
    struct session *session_next;   // disc hash
    struct bfdhdr bfdh;
    struct sockaddr_in laddr;       // 本端地址
    struct sockaddr_in raddr;       // 远端地址
        
    unsigned int des_min_tx_time;           /* 最小发送间隔 */
    unsigned int req_min_rx_time;           /* 最小接收间隔 */
    unsigned int req_min_rx_echo_time;      /* 最小echo报文接收间隔 */
    unsigned int act_tx_intv;               /* 实际发送间隔 */
    unsigned int act_rx_intv;               /* 实际接收间隔 */
    unsigned int detect_time;               /* 检测时间 */
    unsigned int remote_req_tx_time;          /* 对端期望发送间隔 */
    unsigned int remote_req_rx_time;          /* 对端要求接收间隔 */    

    struct epoll_callback_data tx_timer;
    struct epoll_callback_data rx_timer;
    struct epoll_callback_data sockfd;
    
    pthread_mutex_t bfd_mutex;  //互斥锁
    pthread_cond_t  bfd_cond;   //条件变量
    struct msg_node *msg_head;       //消息队列
    pthread_t  bfd_work_thread;                //工作线程

    int del_flag;       //删除标志
    
	char	 key[56];		            // key 值        
};

/* bfd fsm event */
#define    BFD_EVENT_START                      0  // 初始事件
#define    BFD_EVENT_RECV_DOWN                  1  // 收到对端down事件
#define    BFD_EVENT_RECV_INIT                  2  // 收到对端init事件
#define    BFD_EVENT_RECV_UP                    3  // 收到对端up事件
#define    BFD_EVENT_TIMER_EXPIRE               4  // 收到对端admin_down事件
#define    BFD_EVENT_RECV_ADMINDOWN             5  // 收到接收计时器超时事件
#define    BFD_EVENT_MAX                        6


#define BFD_SESSION_HASH_SIZE      255
#define BFD_MSG_BUFFER_SIZE 512

struct bfd_master
{
	struct session *session_tbl[BFD_SESSION_HASH_SIZE];     // my_disc hash
	struct session *neigh_tbl[BFD_SESSION_HASH_SIZE];       // raddr hash
};

#ifndef NIPQUAD
#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#endif

union bfd_inet_addr {           /* 地址类型 */
    uint32_t all[4];
    uint32_t ip;
    uint32_t ip6[4];
};


struct session_cfg {         /* bfd 会话配置数据 */
    uint32_t local_ip_type;     /* 本地ip类型 */
    union bfd_inet_addr local_ip;   /* 本地ip */
    uint16_t local_port;      /* 本地端口 */

    uint32_t remote_ip_type;    /* 对端ip类型 */
    union bfd_inet_addr remote_ip;  /* 对端IP */
    uint16_t remote_port;     /* 3784 */

   unsigned int detect_multi;   /* 检测倍数 */
   unsigned int des_min_tx_interval;    /* 期待最小发送间隔 */
   unsigned int req_min_rx_interval;    /* 要求最小接收间隔 */
   unsigned int req_min_echo_rx;
   char	 key[56];		// key 值   
};

//消息结构体
struct msg_node{
    struct msg_node *next;
    int msg_type;
};

// BFD消息类型
enum MSGTYPE {
	BFDSessionUp       = 0,	//会话up
	BFDSessionDown     = 1,	//会话down
	BFDSessionDelete   = 2,	//会话delete	
};


// BFD响应消息
typedef struct {
	char msgkey[56];    //消息key值
	char msginfo[100];  //消息原因
	int msgtype;        //消息类型
	
}BFD_RSP;

// BFD会话配置配置信息
typedef struct
{
	uint16_t localPort;		// 本地端口
	uint32_t localIPType;	// 本地IP类型
	uint8_t localIP[16];		// 本地IP地址
	
	uint16_t remotePort;	// 远端端口
	uint32_t remoteIPType;	// 远端IP类型
	uint8_t remoteIP[16];		// 远端IP
	
	uint32_t detectMult;	// 检测次数
	uint32_t desMinTx;		// 最小发送时间
	uint32_t reqMinRx;		// 最小接收时间
	uint32_t reqMinEchoRx;	// echo 报文接收时间
	char	 key[56];		// key 值    
	
} BFD_CFG;

// 定义回调函数
typedef  void(*CALLBACK_FUNC)(BFD_RSP *val);
typedef  void(*LOG_CALLBACK_FUNC)(char *val);

int bfd_init(void);
int bfd_exit(void);
void bfd_add(BFD_CFG *cfg);
void bfd_delete(BFD_CFG *cfg);
void bfd_setCallback(CALLBACK_FUNC pfunc);
void bfd_setLogCallback(LOG_CALLBACK_FUNC pfunc);
void bfd_log(char *msg, int size, const char *fmt, ...);

void bfd_notify(char *msgkey, char *msginfo, int msgtype);
struct session *bfd_session_lookup(uint32_t my_disc, struct sockaddr_in *dst, struct sockaddr_in * src);

void bfd_stop_tx_timer(struct session *bfd_session);
void bfd_start_tx_timer(struct session *bfd_session);
void bfd_stop_rx_timer(struct session *bfd_session);

void *bfd_session_work(void *data);
void *bfd_epoll_work(void *data);

int bfd_fsm_ignore(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);

int bfd_fsm_admindown_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_admindown_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_admindown_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_admindown_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_admindown_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_admindown_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);

int bfd_fsm_down_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_down_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_down_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_down_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_down_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_down_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);

int bfd_fsm_init_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_init_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_init_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_init_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_init_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_init_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);

int bfd_fsm_up_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_up_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_up_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_up_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_up_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);
int bfd_fsm_up_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len);


#endif


