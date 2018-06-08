#include "bfdd.h"

CALLBACK_FUNC callbackSendMsg;      // 消息响应函数指针
LOG_CALLBACK_FUNC log_callback;     // 日志输出函数指针

static pthread_rwlock_t bfd_rwlock;          // 线程读写锁
static pthread_rwlockattr_t bfd_rwlock_attr; // 读写锁属性，写者优先
pthread_t  bfd_rx_thread;                    // bfd报文接收线程
pthread_t  bfd_timing_thread;                // 定时器管理线程

struct bfd_master master;   // 会话控制块
static int bfd_debug_enable = 1;    

int bfd_rx_sock;                             // 接收套接字
static struct sockaddr_in server_addr;       // 监听本地bfd地址

int efd;    // epoll文件描述符，    
struct epoll_event g_event;  // epoll事件
struct epoll_event *g_events; 

char msg_buf[BFD_MSG_BUFFER_SIZE] = {0};    // 主线程消息缓存
char rx_thread_buf[BFD_MSG_BUFFER_SIZE] = {0};  // 接受线程消息缓存
char timer_thread_buf[BFD_MSG_BUFFER_SIZE] = {0}; // 定时器处理线程消息缓存


// 获取hash   key
int hash_key(unsigned int my_disc, unsigned int daddr) {
    if (my_disc != 0) 
        return my_disc % BFD_SESSION_HASH_SIZE;
    else 
        return daddr % BFD_SESSION_HASH_SIZE;
}


// 随机生成 My_Disc 
unsigned int bfd_create_mydisc(void) {
    time_t t;
    unsigned int disc = 0;
    srand((unsigned int)time(&t));    
    while(1) {
        disc = rand();
        if(disc != 0)
            break;
    }
    return disc;
}


// 创建发送套接字 
int bfd_create_ctrl_socket(struct session *bfd_session) {
    int on = 1;
	int err = 0;
	int ttl = 255;  // time to live

    // 创建发送套接字 
	if ((bfd_session->tx_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d Error creating control socket. ret = %d, errno : %d",__FUNCTION__,__LINE__, err, errno);
        return -1;
	}

    // 设置SO_REUSEADDR属性
    if((err = setsockopt(bfd_session->tx_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))) != 0) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d Error setsockopt reuseaddr. ret = %d, errno : %d ",__FUNCTION__,__LINE__, err, errno);
        close(bfd_session->tx_sock);
        return -1;
    }
    
    // 设置IP_TTL属性
    if((err = setsockopt(bfd_session->tx_sock, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof (int))) != 0) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d Error setsockopt ip_ttl. ret = %d, errno : %d ",__FUNCTION__,__LINE__, err, errno);
        close(bfd_session->tx_sock);
        return -1;    
    }    

    // 绑定本地地址和端口
    if((err = bind(bfd_session->tx_sock, (struct sockaddr *)&(bfd_session->laddr), sizeof(struct sockaddr_in))) != 0)
    {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d Error bind addr. ret = %d, errno : %d, addr : %u:%u:%u:%u:%hu ",__FUNCTION__,__LINE__, err, errno,
            NIPQUAD(bfd_session->laddr), ntohs(bfd_session->laddr.sin_port));
        close(bfd_session->tx_sock);
        return -1;
    } 
    
    return 0;
}


// 创建新会话
struct session * bfd_session_new(struct session_cfg *session_cfg)
{
    int ret;
	struct session *bfd_session;

    // 判断协议类型
    if (session_cfg->local_ip_type != AF_INET || (session_cfg->remote_ip_type != AF_INET)) {     
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d unsupport ip type, local_ip_type :%u, remote_ip_type : %u ",__FUNCTION__,__LINE__, session_cfg->local_ip_type, 
            session_cfg->remote_ip_type);
        return NULL;
    }

    // 判断远端端口 
    if (session_cfg->remote_port != BFD_LISTENING_PORT) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd remote port invalid, %hu, should be 3784 ",__FUNCTION__,__LINE__, session_cfg->remote_port);
        return NULL;
    }

	bfd_session = malloc(sizeof(struct session));
	if (bfd_session) {
		memset(bfd_session, 0, sizeof(struct session));
        bfd_session->session_next = NULL;
        bfd_session->neigh_next = NULL;

        // 设置本端地址
        bfd_session->laddr.sin_family = AF_INET;
        bfd_session->laddr.sin_addr.s_addr = session_cfg->local_ip.ip;  
        bfd_session->laddr.sin_port = htons(session_cfg->local_port);

        // 设置远端地址
        bfd_session->raddr.sin_family = AF_INET;
        bfd_session->raddr.sin_addr.s_addr = session_cfg->remote_ip.ip;
        bfd_session->raddr.sin_port = htons(session_cfg->remote_port);

        bfd_session->bfdh.version = BFD_VERSION;    // 版本
        bfd_session->bfdh.diag = BFD_DIAG_NO_DIAG;  // 诊断
        bfd_session->bfdh.sta = BFD_STA_DOWN;       // 状态码
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.cplane = 0;
        bfd_session->bfdh.final = 0;
        bfd_session->bfdh.auth = 0;
        bfd_session->bfdh.demand = 0;
        bfd_session->bfdh.mpoint = 0;
        bfd_session->bfdh.detect_mult = session_cfg->detect_multi;
        bfd_session->bfdh.len = BFD_CTRL_LEN;

        bfd_session->bfdh.my_disc = htonl(bfd_create_mydisc());
        while(bfd_session_lookup(bfd_session->bfdh.my_disc, 0, 0)) {
            bfd_session->bfdh.my_disc = htonl(bfd_create_mydisc());
        }
        bfd_session->bfdh.your_disc = 0;
        bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
        bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);
        bfd_session->bfdh.req_min_echo_rx_intv = 0;

        bfd_session->des_min_tx_time = session_cfg->des_min_tx_interval;
        bfd_session->req_min_rx_time = session_cfg->req_min_rx_interval;
        bfd_session->req_min_rx_echo_time = session_cfg->req_min_echo_rx;
        
        bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;
        bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;

        strcpy(bfd_session->key, session_cfg->key);

        // 创建超时检测定时器
        bfd_session->rx_fd.fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        bfd_session->rx_fd.bfd_session = bfd_session;
        bfd_session->rx_fd.flag = 0;        

        // 创建定时发送定时器
        bfd_session->tx_fd.fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        bfd_session->tx_fd.bfd_session = bfd_session;
        bfd_session->tx_fd.flag = 1;                

        if ((bfd_session->tx_fd.fd == -1) || (bfd_session->rx_fd.fd == -1)) 
            bfd_log(&msg_buf[0], 512, "[bfd] %s:%d create epoll fail",__FUNCTION__,__LINE__);
                
        // 添加到epoll检测变量中
        g_event.data.ptr = &(bfd_session->rx_fd); 
        g_event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, bfd_session->rx_fd.fd, &g_event);          

        g_event.data.ptr = &(bfd_session->tx_fd); 
        g_event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, bfd_session->tx_fd.fd, &g_event);          

        // 创建发送套接字 
        ret = bfd_create_ctrl_socket(bfd_session);
        if (ret != 0) {
            epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->tx_fd.fd, NULL);          
            epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->rx_fd.fd, NULL);                      
            close(bfd_session->rx_fd.fd);
            close(bfd_session->tx_fd.fd);            
            close(bfd_session->tx_sock);
            free(bfd_session);            
            bfd_log(&msg_buf[0], 512, "[bfd] %s:%d create bfd ctrl socket fail  ",__FUNCTION__,__LINE__);
            return NULL;
        }        
	}
	else {	
	    bfd_log(&msg_buf[0], 512, "[bfd] %s:%d session malloc failed ",__FUNCTION__,__LINE__);
	    return NULL;
    }

	return bfd_session;
}


// 添加会话 
int bfd_session_add(struct session_cfg *cfg) {
	int key;
	int err = 0;
	struct sockaddr_in addr;
	struct session *bfd_session = NULL;

	addr.sin_addr.s_addr = cfg->remote_ip.ip;
	
    // 判断是否已存在会话，存在则更新参数
    bfd_session = bfd_session_lookup(0, cfg->remote_ip.ip, cfg->local_ip.ip);
    if (bfd_session) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d session update. local_addr : %u:%u:%u:%u, peer_addr : %u:%u:%u:%u ",__FUNCTION__,__LINE__, NIPQUAD(cfg->local_ip.ip), NIPQUAD(cfg->remote_ip.ip));
        bfd_session->bfdh.detect_mult = cfg->detect_multi;
        bfd_change_interval_time(bfd_session, cfg->des_min_tx_interval, cfg->req_min_rx_interval);
        return 0;
    }

    // 创建新的会话 
	bfd_session = bfd_session_new(cfg);
	if (!bfd_session) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d create session fail. ",__FUNCTION__,__LINE__);
		return -1;
    }
    bfd_log(&msg_buf[0], 512, "[bfd] %s:%d create new session success. ",__FUNCTION__,__LINE__);
    

	// 添加到会话表中
    pthread_rwlock_wrlock(&bfd_rwlock);
    key = hash_key(bfd_session->bfdh.my_disc, 0);
    bfd_session->session_next = master.session_tbl[key];
    master.session_tbl[key] = bfd_session;
    
    key = hash_key(0, bfd_session->raddr.sin_addr.s_addr);
    bfd_session->neigh_next = master.neigh_tbl[key];
    master.neigh_tbl[key] = bfd_session;
    pthread_rwlock_unlock(&bfd_rwlock);

    // 会话初始事件
	bfd_fsm_event(bfd_session, BFD_EVENT_START);

	return err;
}


// 删除bfd会话
void bfd_session_delete(struct session *bfd_session) {
    int i, ret = 0;
    unsigned int key;
    
    struct session *session_priv = NULL;
    struct session *session_cur = NULL;
    struct session *neigh_priv = NULL;
    struct session *neigh_cur = NULL;

    pthread_rwlock_wrlock(&bfd_rwlock);   
    key = hash_key(bfd_session->bfdh.my_disc, 0);
    session_cur = master.session_tbl[key];
    
    while(session_cur && session_cur->bfdh.my_disc != bfd_session->bfdh.my_disc) {
        session_priv = session_cur;
        session_cur = session_cur->session_next;
    }

    if (session_priv == NULL)
        master.session_tbl[key] = bfd_session->session_next;
    else 
        session_priv->session_next = bfd_session->session_next; 
    
    key = hash_key(0, bfd_session->raddr.sin_addr.s_addr);
    neigh_cur = master.neigh_tbl[key];
    while(neigh_cur && neigh_cur->bfdh.my_disc != bfd_session->bfdh.my_disc) {
        neigh_priv = neigh_cur;
        neigh_cur = neigh_cur->neigh_next;
    }
    if (neigh_priv == NULL)
        master.neigh_tbl[key] = bfd_session->session_next;
    else 
        neigh_priv->neigh_next = bfd_session->session_next;    
    pthread_rwlock_unlock(&bfd_rwlock);

    // 关掉定时器
    bfd_stop_xmit_timer(bfd_session);
    bfd_stop_expire_timer(bfd_session);

    // 从epoll队列中删除
    epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->rx_fd.fd, NULL);      
    epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->tx_fd.fd, NULL);      

    // 关闭定时器描述符
    close(bfd_session->rx_fd.fd);
    close(bfd_session->tx_fd.fd);

    // 关闭发送套接字
    close(bfd_session->tx_sock);

    // 释放会话
    if (bfd_session) {
        free(bfd_session);
        bfd_session = NULL;
    }
        
    bfd_log(&msg_buf[0], 512, "[bfd] %s:%d delete session success ",__FUNCTION__,__LINE__);

    return ;    
}


// 发送控制报文
int bfd_send_ctrl_packet(struct session *bfd_session)
{
	int ret = 0;
	struct msghdr msg;
	struct iovec iov[1];
	struct bfdhdr bfdh;

    bfd_session->bfdh.req_min_echo_rx_intv = 0;
	memcpy(&bfdh, &(bfd_session->bfdh), sizeof(struct bfdhdr));
	memset(&msg, 0, sizeof(struct msghdr));	
	msg.msg_name = &(bfd_session->raddr);    // 设置目的地址 
	msg.msg_namelen = sizeof(struct sockaddr_in);
	iov[0].iov_base = &bfdh;
	iov[0].iov_len  = sizeof(struct bfdhdr);	
    msg.msg_iov = &iov[0];
    msg.msg_iovlen = 1;
    ret = sendmsg(bfd_session->tx_sock, &msg, 0);   // 发送
    if (ret == -1)
        bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d bfd send ctrl len :%d , errno :%d ",__FUNCTION__,__LINE__, ret, errno);

	return ret;
}


/* 设置发送定时器 */
void bfd_start_xmit_timer(struct session *bfd_session)
{
    int ret;
    time_t t;
	unsigned int jitter;
    struct itimerspec timeval;	
    srand((unsigned int)time(&t));

	// jitter is 0% -> 25%. if detectmult == 1, max 90%, 随机延迟
	jitter = rand();
	jitter = 75 + jitter % ((bfd_session->bfdh.detect_mult == 1 ? 15 : 25) + 1);

    memset(&timeval, 0, sizeof(struct itimerspec));       
    timeval.it_value.tv_sec = ((bfd_session->act_tx_intv * jitter)/100)/1000000;
    timeval.it_value.tv_nsec = (((uint64_t)bfd_session->act_tx_intv * jitter)*10)%1000000000;
    timeval.it_interval.tv_sec = timeval.it_value.tv_sec;
    timeval.it_interval.tv_nsec = timeval.it_value.tv_nsec;

    // 设置发送定时器
    ret = timerfd_settime(bfd_session->tx_fd.fd, 0, &timeval, NULL);    // 相对时间
    if (ret == -1) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d settimer fail，errno : %d",__FUNCTION__,__LINE__, errno);
        return ;
    }

    
    /* bfd_log(&msg_buf[0], 512, "[bfd] %s:%d set xmit timer, sec:%u, nsec : %u, jitter : %u ",__FUNCTION__,__LINE__,((bfd_session->act_tx_intv * jitter)/100)/1000000,
    (((uint64_t)bfd_session->act_tx_intv * jitter)*10)%1000000000, jitter); */

	return ;
}


// 取消发送定时器
void bfd_stop_xmit_timer(struct session *bfd_session) {
    int ret;
    struct itimerspec timeval;  
    memset(&timeval, 0, sizeof(struct itimerspec));       

    ret = timerfd_settime(bfd_session->tx_fd.fd, 0, &timeval, NULL);
    if (ret == -1) 
        bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d settimer fail，errno : %d",__FUNCTION__,__LINE__, errno);

	return;
}


// 重置发送定时器 
void bfd_reset_tx_timer(struct session *bfd_session) {
    // bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d reset tx timer ",__FUNCTION__,__LINE__);
	bfd_stop_xmit_timer(bfd_session);  
	bfd_start_xmit_timer(bfd_session); 
	
	return;
}


// 停止超时定时器
void bfd_stop_expire_timer(struct session *bfd_session) {
    int ret;
    struct itimerspec timeval;  
    memset(&timeval, 0, sizeof(struct itimerspec));       



    //bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d stop expire timer ",__FUNCTION__,__LINE__);
    ret = timerfd_settime(bfd_session->rx_fd.fd, 0, &timeval, NULL);
    if (ret == -1) 
        bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d settimer fail，errno : %d",__FUNCTION__,__LINE__, errno);

	return;
}


// 重置超时定时器
void bfd_reset_expire_timer(struct session *bfd_session) {
    int ret;
    struct itimerspec timeval;  
    memset(&timeval, 0, sizeof(struct itimerspec));       

    // 停止超时检测定时器
    bfd_stop_expire_timer(bfd_session);
   
    // 设置定时
    timeval.it_value.tv_sec = (bfd_session->detect_time)/1000000;
    //timeval.it_value.tv_nsec = (bfd_session->detect_time)%1000000;
 	timeval.it_value.tv_nsec = (((uint64_t)bfd_session->detect_time)*1000)%1000000000;  
 	timeval.it_interval.tv_sec = timeval.it_value.tv_sec;
    timeval.it_interval.tv_nsec = timeval.it_value.tv_nsec;
    ret = timerfd_settime(bfd_session->rx_fd.fd, 0, &timeval, NULL);
	//bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d expire timer sec : %u, nsec : %u ",__FUNCTION__,__LINE__, (bfd_session->detect_time)/1000000, (((uint64_t)bfd_session->detect_time)*1000)%1000000000);
    if (ret == -1) {
        bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d settimer fail，errno : %d",__FUNCTION__,__LINE__, errno);
        return ;
    }

	return;
}


// 定时发送bfd 控制报文 
void bfd_xmit_timeout(struct session *bfd_session) {    
    //一直尝试
	/* reset timer before send processing(avoid self synchronization) */	
	bfd_start_xmit_timer(bfd_session);
	bfd_send_ctrl_packet(bfd_session);


	return;
}


// 会话超时回调函数 
void bfd_detect_timeout(struct session *bfd_session) {
    int del_flag = 0;
    bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d timer out, current sta : %d ",__FUNCTION__,__LINE__, bfd_session->bfdh.sta);
	del_flag = bfd_fsm_event(bfd_session, BFD_EVENT_TIMER_EXPIRE);
	
	return;
}


int bfd_fsm_ignore(struct session *bfd_session) {
    //bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd fsm ignore ",__FUNCTION__,__LINE__);

	return 0;
}


// 收到admin_down
int bfd_fsm_recv_admin_down(struct session *bfd_session) {
    bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd fsm recv_admindown ",__FUNCTION__,__LINE__);

	if (bfd_session->bfdh.sta != BFD_STA_DOWN) {
		/* goes to administratively down */
		bfd_session->bfdh.diag = BFD_DIAG_ADMIN_DOWN;
		bfd_stop_xmit_timer(bfd_session);
		bfd_stop_expire_timer(bfd_session);
	}
	
	return 0;
}


// 会话初始化时间
int bfd_fsm_start(struct session *bfd_session) {
    bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd fsm start ",__FUNCTION__,__LINE__);
	bfd_start_xmit_timer(bfd_session);

	return 0;
}


// 收到down
int bfd_fsm_rcvd_down(struct session *bfd_session) {
   // bfd_log(&rx_thread_buf[0], 512, "[bfd] %s:%d bfd fsm recv down ",__FUNCTION__,__LINE__);

    // 如果本地状态为up的话，收到down事件需要更新diag原因
	if(bfd_session->bfdh.sta == BFD_STA_UP)
	{
		bfd_session->bfdh.diag = BFD_DIAG_NBR_SESSION_DOWN;
	}
	
	return 0;
}


// 收到init
int bfd_fsm_rcvd_init(struct session *bfd_session) {
    //bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd fsm recv init ",__FUNCTION__,__LINE__);
    
	return 0;
}


// 收到up
int bfd_fsm_rcvd_up(struct session *bfd_session) {
    //bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd fsm recv up ",__FUNCTION__,__LINE__);
    
	return 0;
}


// 定时器超时
int bfd_fsm_timer_expire(struct session *bfd_session) {
    bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bfd Timeout. time = %u usec, peer-addr : %u:%u:%u:%u ",__FUNCTION__,__LINE__, bfd_session->detect_time, 
    	NIPQUAD(bfd_session->raddr.sin_addr.s_addr));
	bfd_session->bfdh.diag = BFD_DIAG_CTRL_TIME_EXPIRED;

	// 重置定时器
	bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
	bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);

	return 0;
}


// 改变时间间隔
void bfd_change_interval_time(struct session *bfd_session, unsigned int tx, unsigned int rx) {
	/* Section 6.7.3 Description */
	if (bfd_session->bfdh.sta == BFD_STA_UP && (tx > ntohl(bfd_session->bfdh.des_min_tx_intv))) {
		bfd_session->bfdh.poll = 1;
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d BFD Poll Sequence is started(tx_intv increase) ",__FUNCTION__,__LINE__);
	}
	else {
		bfd_session->act_tx_intv = tx < ntohl(bfd_session->peer_req_rx_time) ? ntohl(bfd_session->peer_req_rx_time) : tx;
		bfd_reset_tx_timer(bfd_session); 
	}

	if (bfd_session->bfdh.sta == BFD_STA_UP && (rx < ntohl(bfd_session->bfdh.req_min_rx_intv))) {
		bfd_session->bfdh.poll = 1;		
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d BFD Poll Sequence is started(rx_intv change)",__FUNCTION__,__LINE__);
	}
	else {
		bfd_session->act_rx_intv = rx;
	}

	bfd_session->bfdh.des_min_tx_intv = htonl(tx);
	bfd_session->bfdh.req_min_rx_intv = htonl(rx);

	return;
}


/* BFD Finite State Machine structure

                                  +--+
                                  |  | UP, ADMIN DOWN, TIMER
                                  |  V
                          DOWN  +------+  INIT
                   +------------|      |------------+
                   |            | DOWN |            |
                   |  +-------->|      |<--------+  |
                   |  |         +------+         |  |
                   |  |                          |  |
                   |  |               ADMIN DOWN,|  |
                   |  |ADMIN DOWN,          DOWN,|  |
                   |  |TIMER                TIMER|  |
                   V  |                          |  V
                 +------+                      +------+
            +----|      |                      |      |----+
        DOWN|    | INIT |--------------------->|  UP  |    |INIT, UP
            +--->|      | INIT, UP             |      |<---+
                 +------+                      +------+
*/

struct
{
	int (*func)(struct session *);
	int next_state;
} FSM[BFD_STA_MAX][BFD_EVENT_MAX]
={
	{
        // admindown
		{bfd_fsm_ignore, BFD_STA_ADMINDOWN},				// Start 
		{bfd_fsm_ignore, BFD_STA_ADMINDOWN},				// Received_Down 
		{bfd_fsm_ignore, BFD_STA_ADMINDOWN},				// Received_Init 
		{bfd_fsm_ignore, BFD_STA_ADMINDOWN},				// Received_Up 
		{bfd_fsm_ignore, BFD_STA_ADMINDOWN},				// TimerExpired
		{bfd_fsm_recv_admin_down, BFD_STA_ADMINDOWN},	    // Received_AdminDown 
	},
	{
		// down
		{bfd_fsm_start, BFD_STA_DOWN},						// Start，
		{bfd_fsm_rcvd_down, BFD_STA_INIT},					// Received_Down 
		{bfd_fsm_rcvd_init, BFD_STA_UP},					// Received_Init 
		{bfd_fsm_ignore, BFD_STA_DOWN},						// Received_Up 
		{bfd_fsm_ignore, BFD_STA_DOWN},						// TimerExpired 
		{bfd_fsm_recv_admin_down, BFD_STA_DOWN},		    // Received_AdminDown 
	},
	{
		// init
		{bfd_fsm_ignore, BFD_STA_INIT},						// Start 
		{bfd_fsm_ignore, BFD_STA_INIT},						// Received_Down 
		{bfd_fsm_rcvd_init, BFD_STA_UP},					// Received_Init 
		{bfd_fsm_rcvd_up, BFD_STA_UP},						// Received_Up 
		{bfd_fsm_timer_expire, BFD_STA_DOWN},				// TimerExpired 
		{bfd_fsm_recv_admin_down, BFD_STA_DOWN},		    // Received_AdminDown 
	},
	{
		// Up
		{bfd_fsm_ignore, BFD_STA_UP},						// Start 
		{bfd_fsm_rcvd_down, BFD_STA_DOWN},					// Received_Down 
		{bfd_fsm_ignore, BFD_STA_UP},						// Received_Init 
		{bfd_fsm_ignore, BFD_STA_UP},						// Received_Up 
		{bfd_fsm_timer_expire, BFD_STA_DOWN},				// TimerExpired 
		{bfd_fsm_recv_admin_down, BFD_STA_DOWN},		    // Received_AdminDown 
	},
};


// bfd 状态机处理函数 
int bfd_fsm_event(struct session *bfd_session, int bfd_event)
{
	int next_state, old_state;
	int del_flag = 0;

	old_state = bfd_session->bfdh.sta;
	next_state = (*(FSM[bfd_session->bfdh.sta][bfd_event].func))(bfd_session);
    
	if (!next_state)
		bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][bfd_event].next_state;
	else
		bfd_session->bfdh.sta = next_state;

    // 如果会话建立，变更定时器间隔 
	if (bfd_session->bfdh.sta != old_state) {
        if (bfd_session->bfdh.sta == BFD_STA_UP && old_state != BFD_STA_UP) {
            bfd_change_interval_time(bfd_session, bfd_session->des_min_tx_time, bfd_session->req_min_rx_time);
            bfd_notify(bfd_session->key, "", BFDSessionUp);
            bfd_log(&msg_buf[0], 512, "[BFD] %s %d session up. local_ip : %u:%u:%u:%u, remote_ip:: %u:%u:%u:%u ",__FUNCTION__, __LINE__,
                NIPQUAD(bfd_session->laddr.sin_addr.s_addr), NIPQUAD(bfd_session->raddr.sin_addr.s_addr));
        }
                
	    // 会话异常 
		if ((bfd_session->bfdh.sta != BFD_STA_UP) && (old_state == BFD_STA_UP)) {
		    del_flag = 1;
            switch(bfd_session->bfdh.diag) {
                case BFD_DIAG_CTRL_TIME_EXPIRED:
                    bfd_notify(bfd_session->key, "timer expired", BFDSessionDown);            
                    break;

                case BFD_DIAG_NBR_SESSION_DOWN:
                    bfd_notify(bfd_session->key, "neighbour session down", BFDSessionDown);            
                    break;

                case BFD_DIAG_ADMIN_DOWN  :
                    bfd_notify(bfd_session->key, "admin down", BFDSessionDown);            
                    break;
                default:
                    bfd_notify(bfd_session->key, "default down", BFDSessionDown);            
                    break;                
            }
        bfd_log(&msg_buf[0], 512, "[BFD] %s %d session down. local_ip : %u:%u:%u:%u, remote_ip:: %u:%u:%u:%u ",__FUNCTION__, __LINE__,
                NIPQUAD(bfd_session->laddr.sin_addr.s_addr), NIPQUAD(bfd_session->raddr.sin_addr.s_addr));
		}

		if(bfd_session->bfdh.sta != BFD_STA_UP) {
			bfd_change_interval_time(bfd_session, BFD_DEFAULT_TX_INTERVAL, BFD_DEFAULT_RX_INTERVAL);
			/* Cancel Expire timer, 超时则需停止 */
			bfd_stop_expire_timer(bfd_session);
		}

		// Reset Diagnostic Code 
		if (old_state == BFD_STA_DOWN) {
			bfd_session->bfdh.diag = BFD_DIAG_NO_DIAG;
		}
	}

	return del_flag;
}


// 会话查找
struct session *bfd_session_lookup(uint32_t my_disc, uint32_t dst, uint32_t src) {
	int key;
	struct session *bfd_session = NULL;
    pthread_rwlock_rdlock(&bfd_rwlock);
	if (my_disc){
		key = hash_key(my_disc, 0);
		if (key == -1) {
            return NULL;
		}
		bfd_session = master.session_tbl[key];
		while (bfd_session) {
			if (bfd_session->bfdh.my_disc == my_disc)
				break;
			bfd_session = bfd_session->session_next;
		}
	}
	else {
		key = hash_key(0, dst);
		if (key == -1) {
            return NULL;
		}
		bfd_session = master.neigh_tbl[key];
		while (bfd_session) {            		    
			if (dst == bfd_session->raddr.sin_addr.s_addr && src == bfd_session->laddr.sin_addr.s_addr)
			    break;
			bfd_session = bfd_session->neigh_next;
		}
	}
    pthread_rwlock_unlock(&bfd_rwlock);

	if (bfd_session == NULL && dst != 0)
        bfd_log(&msg_buf[0], 512, "[BFD] %s %d addr not match, dst : %u:%u:%u:%u, raddr : %u:%u:%u:%u",__FUNCTION__,__LINE__, NIPQUAD(dst),NIPQUAD(src));             

	return bfd_session;
}


// bfd报文处理函数
int bfd_recv_ctrl_packet(struct sockaddr_in *client_addr, struct sockaddr_in *server_addr, char *buffer, int len) {
    struct bfdhdr *bfdh;
    struct session *bfd_session;
    unsigned char old_poll_bit;
    int poll_seq_end = 0;
    int del_flag = 0;
    
    bfdh = (struct bfdhdr *)buffer;
    
    /* If the Length field is greater than the payload of the */
    /* encapsulating protocol, the packet MUST be discarded. */    
    // 判断接收长度与报文长度是否相等
    if(bfdh->len > len)
    {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d length is too short. Discarded. bfdh->len :%d > recv_len :%d",__FUNCTION__,__LINE__, bfdh->len, len);
        return -1;
    }
    
    /* Section 6.7.6 check */    
    /* If the version number is not correct (1), the packet MUST be discarded. */    
    // 判断版本号是否正确
    if(bfdh->version != BFD_VERSION)
    {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d bfd packet wrong version : %u ",__FUNCTION__,__LINE__, bfdh->version);
        return -1;
    }
    
    /* If the Length field is less than the minimum correct value (24 if */
    /* the A bit is clear, or 26 if the A bit is set), the packet MUST be */
    /* discarded. */    
    // 判断报文长度是否正确
    if((!bfdh->auth && bfdh->len != BFD_CTRL_LEN) || (bfdh->auth && bfdh->len < BFD_CTRL_AUTH_LEN))
    {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d bfd packet length (%d) not right. Discarded ",__FUNCTION__,__LINE__, bfdh->len);
        return -1;
    }
        
    /* If the Detect Mult field is zero, the packet MUST be discarded. */
    // 检查字段是否合法
    if(bfdh->detect_mult == 0)
    {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d Detect Multi field is zero. Discarded ",__FUNCTION__,__LINE__);
        return -1;
    }
    
    /* If the My Discriminator field is zero, the packet MUST be discarded. */
    // 检查 my_disc是否合法
    if(bfdh->my_disc == 0)
    {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d My Discriminator field is zero. Discarded ",__FUNCTION__,__LINE__);
        return -1;
    }
    
    /* If the Your Discriminator field is nonzero, it MUST be used to */
    /* select the session with which this BFD packet is associated.  If */
    /* no session is found, the packet MUST be discarded. */
    // 查找会话表
    if(bfdh->your_disc)
    {
        bfd_session = bfd_session_lookup(bfdh->your_disc, 0, 0);
        if(bfd_session == NULL)
        {
            bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d couldn't find session with Your Discriminator field (%x). Discarded ",__FUNCTION__,__LINE__, bfdh->your_disc);
            return -1;
        }
    }
    else
    {        
        /* If the Your Discriminator field is zero and the State field is not
        Down or AdminDown, the packet MUST be discarded. */
        if(bfdh->sta != BFD_STA_ADMINDOWN && bfdh->sta != BFD_STA_DOWN)
        {
            bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d Received your_disc = 0, while state is not Down or AdminDown. Discarded ",__FUNCTION__,__LINE__);
            return -1;
        }
    
        /* If the Your Discriminator field is zero, the session MUST be
           selected based on some combination of other fields, possibly
           including source addressing information, the My Discriminator
           field, and the interface over which the packet was received.  The
           exact method of selection is application-specific and is thus
           outside the scope of this specification.  If a matching session is
           not found, a new session may be created, or the packet may be
           discarded.  This choice is outside the scope of this
           specification. 
        */
        bfd_session = bfd_session_lookup(0, client_addr->sin_addr.s_addr, server_addr->sin_addr.s_addr);           
        if(bfd_session == NULL)
        {
            bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d couldn't find session with peer_addr: %u:%u:%u:%u, Discarded ",__FUNCTION__,__LINE__, 
                NIPQUAD(client_addr->sin_addr.s_addr));
            return -1;
        }        
    }
                    
    /* If the A bit is set and no authentication is in use (bfd.AuthType is zero), the packet MUST be discarded.
      If the A bit is clear and authentication is in use (bfd.AuthType is nonzero), the packet MUST be discarded.       
    */
    //如果认证字段置位，discarded
    if(bfdh->auth)
    {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d Auth type is set. Discarded",__FUNCTION__,__LINE__);
        return -1;
    }
    
    /* If the A bit is set, the packet MUST be authenticated under the
           rules of section 6.6, based on the authentication type in use
           (bfd.AuthType.)  This may cause the packet to be discarded. */    
    /* FIXME authentication process */
    
        
    /* Set bfd.RemoteDiscr to the value of My Discriminator. */
    // 更新远端描述符
    bfd_session->bfdh.your_disc = bfdh->my_disc;
    
    /* If the Required Min Echo RX Interval field is zero, the
           transmission of Echo packets, if any, MUST cease. FIXME */
    // 检测echo字段是否合法        
    if (bfdh->req_min_echo_rx_intv != 0) {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d echo_rx_intv not zero, Discarded, peer_req_echo_rx_intv : %x ",__FUNCTION__,__LINE__, bfdh->req_min_echo_rx_intv);
        return -1;
    }
    
    /* If Demand mode is active, a Poll Sequence is being transmitted by
       the local system, and the Final (F) bit in the received packet is
       set, the Poll Sequence MUST be terminated. FIXME */
        
    /* If Demand mode is not active, the Final (F) bit in the received
       packet is set, and the local system has been transmitting packets
       with the Poll (P) bit set, the Poll (P) bit MUST be set to zero in
       subsequent transmitted packets. */
       /* permit session from loopback interface */
    if(!bfd_session->bfdh.demand && bfdh->final && (bfd_session->bfdh.poll)) {
        bfd_session->bfdh.poll = 0;
        poll_seq_end = 1;        
        //停止poll seq
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d BFD Poll Sequence is done. ",__FUNCTION__,__LINE__);
    
        // 更新发送间隔
        bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);
    
        // 更新接收间隔
        bfd_session->act_rx_intv = ntohl(bfd_session->bfdh.req_min_rx_intv);
    }

    // 更新发送间隔
    bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);

    // 更新检测时长
    bfd_session->detect_time = bfdh->detect_mult *
        (bfd_session->act_rx_intv > ntohl(bfdh->des_min_tx_intv) ?
         bfd_session->act_rx_intv : ntohl(bfdh->des_min_tx_intv));

    // 收到F标志置位的话，重置发送任务计时器
    if (poll_seq_end){
        bfd_reset_tx_timer(bfd_session);
    }
    
    // admindown 状态下，丢弃对端报文
    if (bfd_session->bfdh.sta == BFD_STA_ADMINDOWN)
    {               
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d local sta admindown, discard all received packet ",__FUNCTION__,__LINE__);
        return -1;
    }
    
    /* If received state is AdminDown
        If bfd.SessionState is not Down
         Set bfd.LocalDiag to 3 (Neighbor signaled session down)
         Set bfd.SessionState to Down */
    // 收到admindown报文，更新诊断码     
    if (bfdh->sta == BFD_STA_ADMINDOWN)
    {
        if (bfd_session->bfdh.sta != BFD_STA_DOWN)
        {
            bfd_session->bfdh.diag = BFD_DIAG_NBR_SESSION_DOWN;
        }
    }
    
    /* 状态机处理 */
    if (bfdh->sta == BFD_STA_DOWN){
        del_flag = bfd_fsm_event(bfd_session, BFD_EVENT_RECV_DOWN);
    }
    else if (bfdh->sta == BFD_STA_INIT){
        del_flag = bfd_fsm_event(bfd_session, BFD_EVENT_RECV_INIT);
    }
    else if (bfdh->sta == BFD_STA_UP){
        del_flag = bfd_fsm_event(bfd_session, BFD_EVENT_RECV_UP);
    }
    
    /* If the Demand (D) bit is set and bfd.DemandModeDesired is 1,
       and bfd.SessionState is Up, Demand mode is active. 
       if receive D bit set, Discarded FIXME */        
    // 查询模式报文，丢弃
    if (bfdh->demand) {
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d receive demand mode set, discarded ",__FUNCTION__,__LINE__);
        return -1;
    }    
    /* If the Demand (D) bit is clear or bfd.DemandModeDesired is 0,
       or bfd.SessionState is not Up, Demand mode is not active. */
    else {
        bfd_session->bfdh.demand = 0;
    }
    
    /* If the Poll (P) bit is set, send a BFD Control packet to the
       remote system with the Poll (P) bit clear, and the Final (F) bit set. */
    // 响应poll sequence
    if (bfdh->poll)
    {
        /* Store old p-bit */
        old_poll_bit = bfd_session->bfdh.poll;    
        bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d BFD: recv Poll Sequence, send final flag ",__FUNCTION__,__LINE__);
    
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        
        bfd_start_xmit_timer(bfd_session);
        bfd_send_ctrl_packet(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;
    }
    
    /* If the packet was not discarded, it has been received for purposes
       of the Detection Time expiration rules in section 6.7.4. */            
    // 重置超时计时器
    if (bfd_session->bfdh.sta == BFD_STA_UP || bfd_session->bfdh.sta == BFD_STA_INIT)
    {
        //bfd_log(&rx_thread_buf[0], 512, "[BFD] %s %d expire timer reset",__FUNCTION__,__LINE__);
        bfd_reset_expire_timer(bfd_session);
    }
    
    // 会话异常
    if (del_flag)
        bfd_session_delete(bfd_session);
                   
    return 0;       
}
    
        
// 创建接收套接字，成功返回0 
int bfd_create_rx_sock(void) {
    int ret;
    int on = 1;      

    // 创建套接字
    bfd_rx_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (bfd_rx_sock == -1) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d create rx socket fail ",__FUNCTION__,__LINE__);
        return -1;
    }

    // 设置监听地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;  
    server_addr.sin_port = htons(BFD_LISTENING_PORT);  

    // 设置SO_REUSEADDR属性
    if ((ret = setsockopt(bfd_rx_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))) != 0) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d setsockopt reuseaddr fail, error : %d ",__FUNCTION__,__LINE__, errno);
        close(bfd_rx_sock);
        return -1;
    }

    // 设置IP_PKTINFO
    if (0 != setsockopt(bfd_rx_sock, IPPROTO_IP, IP_PKTINFO, (char *)&on, sizeof(on))) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d setsockopt ip_pktinfo fail, errno : %d ",__FUNCTION__,__LINE__, errno);
        close(bfd_rx_sock);
        return -1;  
    }

    // 设置IP_RECVTTL
    if(0 != setsockopt(bfd_rx_sock, IPPROTO_IP, IP_RECVTTL, (char *)&on, sizeof(on))) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d setsockopt ip_recvttl fail，errno : %d ",__FUNCTION__,__LINE__, errno);
        close(bfd_rx_sock);
        return -1;    
    }    

    // 绑定本地监听地址
    if (0 != bind(bfd_rx_sock, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in))) {
        bfd_log(&msg_buf[0], 512, "[bfd] %s:%d bind local listening addr fail，errno : %d ",__FUNCTION__,__LINE__, errno);
        close(bfd_rx_sock);
        return -1;
    }

   return 0;
}


//bfd 接收线程 
void *bfd_recv_thread(void *data)
{
    int ret ;
    int recv_len;
    int recv_ttl;
    int addr_len;
	char buffer[512] = {0};        // 接收缓存 
	struct in_pktinfo *pktinfo = NULL;	 // 用于指向获取的本地地址信息 
	struct msghdr msg;
	struct iovec iov[1];    
	struct sockaddr_in client_addr; // 来源地址 
	struct sockaddr_in server_addr; // 本地地址 	
	struct cmsghdr *cmhp;           
	char buff[CMSG_SPACE(sizeof(struct in_pktinfo) + CMSG_SPACE(sizeof(int)))] = {0};   // 控制信息缓存
	struct cmsghdr *cmh = (struct cmsghdr *)buff;   
    addr_len = sizeof(struct sockaddr_in);

    memset(&buffer, 0, sizeof(buffer));
    memset(&msg, 0, sizeof(struct msghdr));
    memset(&iov, 0, sizeof(struct iovec));
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    memset(&client_addr, 0, sizeof(struct sockaddr_in));    

    // 设置允许线程取消
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    
    // 设置延迟取消
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    // 接收bfd报文
    while(1) {
        pthread_testcancel(); 
        msg.msg_name = &client_addr;
        msg.msg_namelen = addr_len;
        msg.msg_iov = &iov[0];
        msg.msg_iovlen = 1;
        msg.msg_control = cmh;
        msg.msg_controllen = sizeof(buff);    
        iov[0].iov_base = &buffer;
        iov[0].iov_len = sizeof(buffer);                     

        // 超时退出
        recv_len = recvmsg(bfd_rx_sock, &msg, 0);
        if (recv_len > 0)
        {
            // 获取辅助信息
            msg.msg_control = cmh;
            msg.msg_controllen = sizeof(buff);
            for (cmhp = CMSG_FIRSTHDR(&msg); cmhp; cmhp = CMSG_NXTHDR(&msg, cmhp)) {
                if (cmhp->cmsg_level == IPPROTO_IP) {
                    if (cmhp->cmsg_type == IP_PKTINFO) {
                        pktinfo = (struct in_pktinfo *)CMSG_DATA(cmhp);
                        server_addr.sin_family = AF_INET;
                        // 获取头标识目的地址信息 
                        server_addr.sin_addr = pktinfo->ipi_addr;
                    }
                    else if(cmhp->cmsg_type == IP_TTL) {
                        // 获取ttl
                        recv_ttl = *(int *)CMSG_DATA(cmhp);
                    }
                }
            }
            // bfd报文处理、报文检查、状态机、定时器转换
            bfd_recv_ctrl_packet(&client_addr, &server_addr, buffer, recv_len);
        }
        memset(buffer, 0, sizeof(buffer));
        memset(buff, 0, sizeof(buff));
        memset(&server_addr, 0, sizeof(struct sockaddr_in));
        memset(&client_addr, 0, sizeof(struct sockaddr_in));        
        recv_ttl = 0;
    }
    return NULL;
}


// 定时器检测线程主函数
void *bfd_timing_monitor_thread(void *data) {
    int i;
    int ret, fds;
    uint64_t value;
    struct time_callback_arg *arg;

    // 设置允许线程取消
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    // 设置延迟取消
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    
    while(1) {
        // 设置线程取消
        pthread_testcancel(); 
        fds = epoll_wait(efd, g_events, BFD_SESSION_HASH_SIZE, -1);
        for (i = 0; i<fds; i++) {    
            arg = (struct time_callback_arg *)g_events[i].data.ptr;
            if (g_events[i].events & EPOLLIN) {   
                ret = read(arg->fd, &value, sizeof(uint64_t));
                if (ret == -1) 
                    bfd_log(&timer_thread_buf[0], 512, "[bfd] %s:%d read return -1, errno :%d ",__FUNCTION__, __LINE__, errno);
                if (!arg->flag) {
                    // 检测定时器超时
                    bfd_detect_timeout(arg->bfd_session);                    
                }
                else {
                    // 发送定时器超时
                    bfd_xmit_timeout(arg->bfd_session);
                }
            }            
        }        
    }
    
    return NULL;
}


// 设置回调函数
void bfd_setCallback(CALLBACK_FUNC pfunc) {
		callbackSendMsg = pfunc;	
}


// 设置回调函数
void bfd_setLogCallback(LOG_CALLBACK_FUNC pfunc) {
		log_callback = pfunc;	
}


// 发送信息
void bfd_notify(char *msgkey, char *msginfo, int msgtype) {
    BFD_RSP rsp;
    strncpy(rsp.msgkey, msgkey, 56);
    strncpy(rsp.msginfo, msginfo, 56);
    rsp.msgtype = msgtype;

    callbackSendMsg(&rsp);

    return ;
}


// 打印日志
void bfd_log(char *msg, int size, const char *fmt, ...) {
    va_list ap;    
    // 将消息缓存置零
    memset(msg, 0, size);   
    va_start(ap, fmt);
    // 写入消息
    vsnprintf(msg, size, fmt, ap);
    va_end(ap);
    // 调用go log函数
    log_callback(msg);

    return ;
}


// 配置参数打印
void bfd_session_cfg_dump(struct session_cfg *session_cfg) {
    bfd_log(&msg_buf[0], 512,"[bfd] %s:%d local_ip_type : %u "
              "local_port :%hu "
              "local_ip : %u:%u:%u:%u "
              "remote_ip_type : %u "
              "remote_port : %hu "
              "remote_ip : %u:%u:%u:%u "
              "detect_mult : %u "
              "des_min_tx : %u "
              "req_min_rx : %u "
              "req_min_echo_rx : %u "
              "key : %s ",
              __FUNCTION__, __LINE__,
              session_cfg->local_ip_type, session_cfg->local_port, NIPQUAD(session_cfg->local_ip),
              session_cfg->remote_ip_type, session_cfg->remote_port, NIPQUAD(session_cfg->remote_ip),
              session_cfg->detect_multi, session_cfg->des_min_tx_interval, 
              session_cfg->req_min_rx_interval, session_cfg->req_min_echo_rx, session_cfg->key);
}

void bfd_delete(BFD_CFG *cfg){
	return;
}


// 添加bfd配置
void bfd_add(BFD_CFG *cfg) {
	uint32_t src, dst;
	int ret = 0;
	src = inet_addr(cfg->localIP);
	dst = inet_addr(cfg->remoteIP);

    struct session_cfg  val;
    val.local_ip_type = cfg->localIPType;
    val.local_port = cfg->localPort;
    val.remote_ip_type = cfg->remoteIPType;
    val.remote_port = cfg->remotePort;
    val.detect_multi = cfg->detectMult;
    val.des_min_tx_interval = cfg->desMinTx * 1000;
    val.req_min_rx_interval = cfg->reqMinRx * 1000;
    val.req_min_echo_rx = cfg->reqMinEchoRx;
    val.local_ip.ip = src;
    val.remote_ip.ip = dst;    
    strncpy(val.key, cfg->key, 55);
    bfd_session_cfg_dump(&val);
    if (val.remote_port != 3784) {
       // bfd_notify(val.key, "bfd session port wrong, remote port != 3784", HaBFDSessionCreateFailRsp);
        bfd_log(&msg_buf[0], 512,"[bfd] %s:%d wrong remote port :%hu, should be 3784 ",__FUNCTION__, __LINE__, val.remote_port);
        return ;
    }
    ret = bfd_session_add(&val);
    if ( ret != 0) {
      //  bfd_notify(val.key, "bfd add session fail", HaBFDSessionCreateFailRsp);
    }
    
    return ;    
}


// bfd 初始化，成功返回0
int bfd_init(void) {
    int ret;   

    // 创建 efd 文件描述
    efd = epoll_create1(0);
    if (efd == -1) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d create epoll fail ",__FUNCTION__, __LINE__);
        return -1;
    }
    bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d create epoll success ",__FUNCTION__, __LINE__);    
    
    g_events = (struct epoll_event *)calloc(BFD_SESSION_HASH_SIZE, sizeof(struct epoll_event));
    if (g_events == NULL) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d calloc fail ",__FUNCTION__, __LINE__);
        close(efd);
        return -1;
    }
    
    // 会话表初始化
    memset(&master, 0, sizeof(struct bfd_master));    
    
    //接收套接字初始化
    ret = bfd_create_rx_sock();
    if (ret != 0) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d create rx_sock fail ",__FUNCTION__, __LINE__);
        goto err1;
    }

    // 读写锁属性初始化
    pthread_rwlockattr_init(&bfd_rwlock_attr);
    // 设置写者优先
    pthread_rwlockattr_setkind_np(&bfd_rwlock_attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    // 读写锁初始化
    ret = pthread_rwlock_init(&bfd_rwlock, &bfd_rwlock_attr);
    
    // 创建接收线程
    ret = pthread_create(&bfd_rx_thread, NULL, bfd_recv_thread, NULL);
    if (ret != 0 ) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d thread create fail ",__FUNCTION__, __LINE__);   
        goto err;
    }

    // 创建定时器监控线程
    ret = pthread_create(&bfd_timing_thread, NULL, bfd_timing_monitor_thread, NULL);
    if (ret != 0 ) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d bfd timing thread create fail ",__FUNCTION__, __LINE__);        
        goto err;
    }
    return 0;
    
err:    
    pthread_rwlockattr_destroy(&bfd_rwlock_attr);    // 读写锁属性注销
    pthread_rwlock_destroy(&bfd_rwlock);            // 读写锁注销
    
    pthread_join(bfd_rx_thread, NULL);              // 线程取消
    pthread_join(bfd_timing_thread, NULL);    
    
    close(bfd_rx_sock);   // 关闭套接字
    
err1:
    close(efd);  // 关闭epoll描述符
    if (g_events) {
        free(g_events); // 释放内存
        g_events = NULL;
    }

    return ret;
}


// bfd退出，资源释放
int bfd_exit() {
    int i, ret = 0;
    unsigned int disc, addr, key;
    
    struct session *bfd_session;
    struct session *session_next;
    struct session *neigh;
    struct session *neigh_priv;

    // 释放bfd会话
    pthread_rwlock_wrlock(&bfd_rwlock);
    for (i = 0; i < BFD_SESSION_HASH_SIZE; i++) {
        bfd_session = master.session_tbl[i];
        while (bfd_session != NULL) {
            master.session_tbl[i] = bfd_session->session_next;           
                
            key = hash_key(0, bfd_session->raddr.sin_addr.s_addr);
            neigh_priv = NULL;
            neigh = master.neigh_tbl[key];
            while (neigh) {
                if (neigh->bfdh.my_disc == bfd_session->bfdh.my_disc) {
                    if (neigh_priv != NULL) 
                        neigh_priv->neigh_next = neigh->neigh_next;
                    else
                        master.neigh_tbl[key] = neigh->neigh_next;                
                    break;                        
                }
                else {
                    neigh_priv = neigh;
                    neigh = neigh->neigh_next;
                }
            }
            // 关掉定时器
            bfd_stop_xmit_timer(bfd_session);
            bfd_stop_expire_timer(bfd_session);
            
            // 从epoll 队列中取消
            epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->rx_fd.fd, NULL);      
            epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->tx_fd.fd, NULL);      
            
            // 关闭定时器描述符
            close(bfd_session->rx_fd.fd);
            close(bfd_session->tx_fd.fd);
            
            // 关闭发送套接字
            close(bfd_session->tx_sock);

            // 释放会话                           
            bfd_session->session_next = NULL;
            bfd_session->neigh_next = NULL;
            free(bfd_session);            
            bfd_session = master.session_tbl[i];
        }       
    }
    pthread_rwlock_unlock(&bfd_rwlock);

    // 通知线程退出    
    bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d pthread cancel bfd_rx_thread ",__FUNCTION__, __LINE__);
    bfd_log(&msg_buf[0], sizeof(msg_buf), "[bfd] %s:%d pthread destroy rwlock and rwlock_attr ",__FUNCTION__, __LINE__);
    pthread_cancel(bfd_rx_thread);
    pthread_cancel(bfd_timing_thread);
    pthread_join(bfd_rx_thread, NULL);
    pthread_join(bfd_timing_thread, NULL);       
    pthread_rwlock_destroy(&bfd_rwlock);    // 读写锁注销
    pthread_rwlockattr_destroy(&bfd_rwlock_attr);    // 读写锁属性注销

    // 关闭文件描述
    close(efd);
    if (g_events) {
        free(g_events);
        g_events = NULL;
    }
    close(bfd_rx_sock);
    return ret;
}

#if 0
int bfd_test(int opt) {
    int ret;

    struct session_cfg test;
    test.local_ip_type = AF_INET;
    test.remote_ip_type = AF_INET;
    test.des_min_tx_interval = 31000;	// 500us
    test.req_min_rx_interval = 31000;	// 500us,
    test.req_min_echo_rx = 0;    
    test.remote_port = 3784;
    test.detect_multi = 2;
    if (opt == 1) {
	 	// 配置A
		log_info("10.251.254.2 --> 10.251.254.1 ");
		test.local_ip.ip = inet_addr("10.251.254.2");
     	test.remote_ip.ip = inet_addr("10.251.254.1");
	    test.local_port = 4002;   		
	}   
	else {
		log_info("10.251.254.1 --> 10.251.254.2 ");	
		test.local_ip.ip = inet_addr("10.251.254.1");
   		test.remote_ip.ip = inet_addr("10.251.254.2");
   		test.local_port = 4000;
    	
	}
    ret = bfd_session_add(&test);     
	if (ret != 0)
		log_info("add session fail ");

	return ret;
}
#endif
