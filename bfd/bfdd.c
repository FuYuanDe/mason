#include "bfdd.h"

CALLBACK_FUNC callbackSendMsg;      // 消息响应函数指针
LOG_CALLBACK_FUNC log_callback;     // 日志输出函数指针

struct bfd_master master;   // 会话控制块
static pthread_mutex_t bfd_session_lock = PTHREAD_MUTEX_INITIALIZER;    //会话控制块保护锁

int efd;    // epoll文件描述符，    
struct epoll_event g_event;  // epoll事件
struct epoll_event *g_events; 
pthread_t epoll_thread;                      //epoll监听线程

char msg_buf[BFD_MSG_BUFFER_SIZE] = {0};     //消息缓存


//获取hash   key
int hash_key(unsigned int my_disc, unsigned int daddr) {
    if (my_disc != 0) 
        return my_disc % BFD_SESSION_HASH_SIZE;
    else 
        return daddr % BFD_SESSION_HASH_SIZE;
}


//随机生成 My_Disc 
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


//创建发送套接字 
int bfd_create_ctrl_socket(struct session *bfd_session) {
    int on = 1;
	int err = 0;
	int ttl = 255;  

    //创建发送套接字 
	if ((bfd_session->sockfd.fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        bfd_log(&msg_buf[0], 512, " %s:%d Error creating control socket. ret = %d, errno : %d",__FUNCTION__,__LINE__, err, errno);
        return -1;
	}

    //设置SO_REUSEADDR属性
    if((err = setsockopt(bfd_session->sockfd.fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on))) != 0) {
        bfd_log(&msg_buf[0], 512, " %s:%d Error setsockopt reuseaddr. ret = %d, errno : %d ",__FUNCTION__,__LINE__, err, errno);
        close(bfd_session->sockfd.fd);
        return -1;
    }
    
    //设置IP_TTL属性
    if((err = setsockopt(bfd_session->sockfd.fd, IPPROTO_IP, IP_TTL, (char *)&ttl, sizeof (int))) != 0) {
        bfd_log(&msg_buf[0], 512, " %s:%d Error setsockopt ip_ttl. ret = %d, errno : %d ",__FUNCTION__,__LINE__, err, errno);
        close(bfd_session->sockfd.fd);
        return -1;    
    }    

    //绑定本地地址和端口
    if((err = bind(bfd_session->sockfd.fd, (struct sockaddr *)&(bfd_session->laddr), sizeof(struct sockaddr_in))) != 0)
    {
        bfd_log(&msg_buf[0], 512, " %s:%d Error bind addr. ret = %d, errno : %d, addr : %u:%u:%u:%u:%hu ",__FUNCTION__,__LINE__, err, errno,
            NIPQUAD(bfd_session->laddr), ntohs(bfd_session->laddr.sin_port));
        close(bfd_session->sockfd.fd);
        return -1;
    } 
    
    return 0;
}


//创建新会话
struct session *bfd_session_new(struct session_cfg *session_cfg) {
    int ret, err;
	struct session *bfd_session = NULL;
	struct epoll_event ep_event; 
	struct msg_node *msg = NULL;
	struct msg_node *msg_priv = NULL;

    //判断协议类型
    if (session_cfg->local_ip_type != AF_INET || (session_cfg->remote_ip_type != AF_INET)) {     
        bfd_log(&msg_buf[0], 512, " %s:%d unsupport ip type, local_ip_type :%u, remote_ip_type : %u ",__FUNCTION__,__LINE__, session_cfg->local_ip_type, 
            session_cfg->remote_ip_type);
        return NULL;
    }

	bfd_session = calloc(1, sizeof(struct session));
	if (bfd_session) {
        bfd_session->session_next = NULL;
        bfd_session->neigh_next = NULL;

        //设置本端地址
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
        bfd_session->bfdh.final = 0;
        bfd_session->bfdh.cplane = 0;
        bfd_session->bfdh.auth = 0;
        bfd_session->bfdh.demand = 0;
        bfd_session->bfdh.mpoint = 0;
        bfd_session->bfdh.detect_mult = session_cfg->detect_multi;
        bfd_session->bfdh.len = BFD_CTRL_LEN;

        bfd_session->bfdh.my_disc = htonl(bfd_create_mydisc());
        while(bfd_session_lookup(bfd_session->bfdh.my_disc, 0, 0)) {
            bfd_session->bfdh.my_disc = htonl(bfd_create_mydisc());
        }
        
        bfd_session->bfdh.your_disc = htonl(0);
        bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
        bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);
        bfd_session->bfdh.req_min_echo_rx_intv = htonl(0);

        bfd_session->des_min_tx_time = session_cfg->des_min_tx_interval;
        bfd_session->req_min_rx_time = session_cfg->req_min_rx_interval;
        bfd_session->req_min_rx_echo_time = session_cfg->req_min_echo_rx;
        
        bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;
        bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;

        bfd_session->msg_head = NULL;
      //  bfd_session->servicetype = session_cfg->service_type;
        strncpy(bfd_session->key, session_cfg->key, 56);

        // 创建发送套接字 
        ret = bfd_create_ctrl_socket(bfd_session);        
        bfd_session->sockfd.fd_type = MSG_EVENT_SOCKET;        
        bfd_session->sockfd.bfd_session = bfd_session;
        if (ret == -1) {
            free(bfd_session);            
            //bfd_log(&msg_buf[0], 512, " %s:%d create bfd ctrl socket fail  ",__FUNCTION__,__LINE__);
            return NULL;
        }        
        
        // 创建超时定时器
        bfd_session->tx_timer.fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        if(bfd_session->tx_timer.fd == -1)
        {
            close(bfd_session->sockfd.fd);
            free(bfd_session);
            return NULL;
        }
        bfd_session->tx_timer.fd_type = MSG_EVENT_TX_TIMER;
        bfd_session->tx_timer.bfd_session = bfd_session;

        // 创建发送定时器
        bfd_session->rx_timer.fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
        if(bfd_session->rx_timer.fd == -1)
        {
            close(bfd_session->sockfd.fd);
            close(bfd_session->tx_timer.fd);
            free(bfd_session);
            return NULL;
        }
        bfd_session->rx_timer.fd_type = MSG_EVENT_RX_TIMER;
        bfd_session->rx_timer.bfd_session = bfd_session;

        //初始化锁和条件变量                               
        pthread_mutex_init(&bfd_session->bfd_mutex, NULL); 
        pthread_cond_init(&bfd_session->bfd_cond, NULL);


        //创建消息节点并发送初始会话消息
        msg = calloc(1, sizeof(struct msg_node));
        if(msg) {
            msg->next = NULL;
            msg->msg_type = MSG_EVENT_START;
            pthread_mutex_lock(&(bfd_session->bfd_mutex));
        
            //追加消息节点
            if (bfd_session->msg_head == NULL)
                bfd_session->msg_head = msg;
            else {
                msg_priv = bfd_session->msg_head;
                while(1) {
                    if (msg_priv->next != NULL)
                        msg_priv = msg_priv->next;
                    else {
                        msg_priv->next = msg;
                        break;
                    }                
                }
            }   
            bfd_log(msg_buf, sizeof(msg_buf), "%s:%d session add msg ",__FUNCTION__, __LINE__);

            pthread_mutex_unlock(&(bfd_session->bfd_mutex));         
        
            //通知消费者线程
            pthread_cond_signal(&(bfd_session->bfd_cond));  
        }

        //添加到epoll池中
        ep_event.data.ptr = &(bfd_session->tx_timer); 
        ep_event.events = EPOLLIN;
        epoll_ctl(efd, EPOLL_CTL_ADD, bfd_session->tx_timer.fd, &ep_event);          
    
        ep_event.data.ptr = &(bfd_session->rx_timer); 
        ep_event.events = EPOLLIN;       
        epoll_ctl(efd, EPOLL_CTL_ADD, bfd_session->rx_timer.fd, &ep_event);          
        ep_event.data.ptr = &(bfd_session->sockfd); 
        ep_event.events = EPOLLIN | EPOLLET;
        //ep_event.events = EPOLLIN;
        err = epoll_ctl(efd, EPOLL_CTL_ADD, bfd_session->sockfd.fd, &ep_event);                         
	}
	else {	
	    //bfd_log(&msg_buf[0], 512, " %s:%d session malloc failed ",__FUNCTION__,__LINE__);
	    return NULL;
    }

	return bfd_session;
}


//添加会话 
int bfd_session_add(struct session_cfg *cfg) {
	int err = 0;
	int ret, key;
	struct epoll_event ep_event; 
	struct msg_node *msg = NULL;
    struct msg_node *msg1 = NULL;	
	struct msg_node *msg_priv = NULL;
	struct sockaddr_in remote_addr;
	struct sockaddr_in local_addr;
	struct session *bfd_session = NULL;
	struct session *neigh_cur = NULL;
    struct session *neigh_priv = NULL;
    struct session *session_cur = NULL;
    struct session *session_priv = NULL;

	remote_addr.sin_addr.s_addr = cfg->remote_ip.ip;
	remote_addr.sin_port = htons(cfg->remote_port);
	local_addr.sin_addr.s_addr = cfg->local_ip.ip;
	local_addr.sin_port = htons(cfg->local_port);
	
    //判断是否已存在会话，存在则更新参数
    bfd_session = bfd_session_lookup(0, &remote_addr, &local_addr);
    if(bfd_session) {
        //session already exist
        return -1;
    }
    
    //创建新的会话 
	bfd_session = bfd_session_new(cfg);
	if(!bfd_session) {
        //bfd_log(&msg_buf[0], 512, "%s:%d create session fail. ",__FUNCTION__,__LINE__);
		return -1;
    }
    bfd_log(&msg_buf[0], 512, "%s:%d create new session success. ",__FUNCTION__,__LINE__);
    
	//添加到会话表中
    pthread_mutex_lock(&bfd_session_lock);

    key = hash_key(bfd_session->bfdh.my_disc, 0);
    bfd_session->session_next = master.session_tbl[key];
    master.session_tbl[key] = bfd_session;
    
    key = hash_key(0, bfd_session->raddr.sin_addr.s_addr);
    bfd_session->neigh_next = master.neigh_tbl[key];
    master.neigh_tbl[key] = bfd_session;

    pthread_mutex_unlock(&bfd_session_lock);


    //创建工作线程
    ret = pthread_create(&bfd_session->bfd_work_thread, NULL, bfd_session_work, (void *)bfd_session);
    if (ret != 0 ) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), "%s:%d thread create fail ",__FUNCTION__, __LINE__);   

        //从会话链表中移除
        pthread_mutex_lock(&bfd_session_lock); 
        key = hash_key(bfd_session->bfdh.my_disc, 0);
        session_cur = master.session_tbl[key];
        
        while(session_cur && session_cur->bfdh.my_disc != bfd_session->bfdh.my_disc) {
            session_priv = session_cur;
            session_cur = session_cur->session_next;
        }
        
        if (session_priv == NULL)
            master.session_tbl[key] = session_cur->session_next;
        else 
            session_priv->session_next = session_cur->session_next; 
        
        key = hash_key(0, bfd_session->raddr.sin_addr.s_addr);
        neigh_cur = master.neigh_tbl[key];
        while(neigh_cur && neigh_cur->bfdh.my_disc != bfd_session->bfdh.my_disc) {
            neigh_priv = neigh_cur;
            neigh_cur = neigh_cur->neigh_next;
        }
        if (neigh_priv == NULL)
            master.neigh_tbl[key] = neigh_cur->neigh_next;
        else 
            neigh_priv->neigh_next = neigh_cur->neigh_next;    
            
        pthread_mutex_unlock(&bfd_session_lock);    

        //从epoll队列中移除
        epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->rx_timer.fd, NULL);      
        epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->tx_timer.fd, NULL);      
        epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->sockfd.fd, NULL);      
                
        //关闭文件描述符
        close(bfd_session->rx_timer.fd);
        close(bfd_session->tx_timer.fd);
        close(bfd_session->sockfd.fd);
        
        //释放消息队列
        pthread_mutex_lock(&bfd_session->bfd_mutex);
        while(bfd_session->msg_head != NULL) {
            msg1 = bfd_session->msg_head;
            bfd_session->msg_head = msg1->next;
            free(msg1);
            msg1 = NULL;
        }                
        pthread_mutex_unlock(&bfd_session->bfd_mutex); 

        //资源释放
        pthread_mutex_destroy(&bfd_session->bfd_mutex);
        pthread_cond_destroy(&bfd_session->bfd_cond);
        free(bfd_session);
        bfd_session = NULL;
        return -1;
    }
           
	return err;
}

//发送报文
int bfd_send_packet(struct session *bfd_session){
	int ret = 0;
	int addr_len;
    struct sockaddr_in dst;
	char buffer[sizeof(struct bfdhdr)] = {0};

    addr_len = sizeof(struct sockaddr_in);
    memcpy(&dst, &bfd_session->raddr, addr_len);
	memcpy(buffer, &(bfd_session->bfdh), sizeof(struct bfdhdr));

    ret = sendto(bfd_session->sockfd.fd, &buffer, sizeof(struct bfdhdr), 0, (struct sockaddr *)&dst, addr_len);
    
    if (ret == -1)
        bfd_log(&msg_buf[0], 512, " %s:%d bfd send ctrl len :%d , errno :%d ",__FUNCTION__,__LINE__, ret, errno);

	return ret;
}


//开启发送定时器 
void bfd_start_tx_timer(struct session *bfd_session) {
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

    ret = timerfd_settime(bfd_session->tx_timer.fd, 0, &timeval, NULL);    // 相对时间
        
    if (ret == -1) {
        bfd_log(&msg_buf[0], 512, " %s:%d settimer fail，errno : %d",__FUNCTION__,__LINE__, errno);
    }

	return ;
}


//取消发送定时器
void bfd_stop_tx_timer(struct session *bfd_session) {
    int ret;
    struct itimerspec timeval;  
    memset(&timeval, 0, sizeof(struct itimerspec));       

    ret = timerfd_settime(bfd_session->tx_timer.fd, 0, &timeval, NULL);
    
	return;
}


//重置发送定时器 
void bfd_reset_tx_timer(struct session *bfd_session) {
	bfd_stop_tx_timer(bfd_session);  
	bfd_start_tx_timer(bfd_session); 
	
	return;
}


//停止超时定时器
void bfd_stop_rx_timer(struct session *bfd_session) {
    int ret;
    struct itimerspec timeval;  
    memset(&timeval, 0, sizeof(struct itimerspec));       
    
    ret = timerfd_settime(bfd_session->rx_timer.fd, 0, &timeval, NULL);

	return;
}


//重置超时定时器
void bfd_reset_rx_timer(struct session *bfd_session) {
    int ret;
    struct itimerspec timeval;  
    memset(&timeval, 0, sizeof(struct itimerspec));       

    //停止超时检测定时器
    bfd_stop_rx_timer(bfd_session);
   
    //设置定时
    timeval.it_value.tv_sec = (bfd_session->detect_time)/1000000;
 	timeval.it_value.tv_nsec = (((uint64_t)bfd_session->detect_time)*1000)%1000000000;  
 	timeval.it_interval.tv_sec = timeval.it_value.tv_sec;
    timeval.it_interval.tv_nsec = timeval.it_value.tv_nsec;
    ret = timerfd_settime(bfd_session->rx_timer.fd, 0, &timeval, NULL);
	//bfd_log(&msg_buf[0], BFD_MSG_BUFFER_SIZE, "%s:%d expire time sec : %u, nsec : %lu ",__FUNCTION__,__LINE__, (bfd_session->detect_time)/1000000, (((uint64_t)bfd_session->detect_time)*1000)%1000000000);

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
	int (*func)(struct session *, struct bfdhdr *,int);
	int next_state;
} FSM[BFD_STA_MAX][BFD_EVENT_MAX]
={
	{
        //admindown
		{bfd_fsm_ignore,  BFD_STA_ADMINDOWN},				//Start 
		{bfd_fsm_ignore,  BFD_STA_ADMINDOWN},				//Received_Down 
		{bfd_fsm_ignore,  BFD_STA_ADMINDOWN},				//Received_Init 
		{bfd_fsm_ignore,  BFD_STA_ADMINDOWN},				//Received_Up 
		{bfd_fsm_ignore,  BFD_STA_ADMINDOWN},				//TimerExpired
		{bfd_fsm_ignore,  BFD_STA_ADMINDOWN},	            //Received_AdminDown 
	},
	{
		//down
		{bfd_fsm_down_rcvd_start, BFD_STA_DOWN},			//Start，
		{bfd_fsm_down_rcvd_down,  BFD_STA_INIT},			//Received_Down 
		{bfd_fsm_down_rcvd_init,  BFD_STA_UP},				//Received_Init 
		{bfd_fsm_ignore,          BFD_STA_DOWN},			//Received_Up 
		{bfd_fsm_ignore,          BFD_STA_DOWN},			//TimerExpired 
		{bfd_fsm_ignore,          BFD_STA_DOWN},		    //Received_AdminDown 
	},
	{
		//init
		{bfd_fsm_ignore,            BFD_STA_INIT},			//Start 
		{bfd_fsm_init_rcvd_down,    BFD_STA_INIT},			//Received_Down 
		{bfd_fsm_init_rcvd_init,    BFD_STA_UP},			//Received_Init 
		{bfd_fsm_init_rcvd_up,      BFD_STA_UP},			//Received_Up 
		{bfd_fsm_init_rcvd_time_expire, BFD_STA_DOWN},		//TimerExpired 
		{bfd_fsm_init_rcvd_admindown,   BFD_STA_DOWN},      //Received_AdminDown 
	},
	{
		//Up
		{bfd_fsm_ignore,        BFD_STA_UP},				//Start 
		{bfd_fsm_up_rcvd_down,  BFD_STA_DOWN},				//Received_Down 
		{bfd_fsm_up_rcvd_init,  BFD_STA_UP},				//Received_Init 
		{bfd_fsm_up_rcvd_up,    BFD_STA_UP},				//Received_Up 
		{bfd_fsm_up_rcvd_time_expire, BFD_STA_DOWN},		//TimerExpired 
		{bfd_fsm_up_rcvd_admindown,   BFD_STA_DOWN},		//Received_AdminDown 
	},
};

int bfd_fsm_ignore(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    return 0;
}


int bfd_fsm_down_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len) {
    bfd_start_tx_timer(bfd_session);
    //bfd_log(&msg_buf[0], 512, "%s %d session start",__FUNCTION__,__LINE__);
    return 0;
}


int bfd_fsm_down_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len) {
    int old_poll_bit;
    int old_state;

    //检查对端是否携带正确的会话描述符    
    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
        return -1;

    //状态变更 down --> init
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_DOWN].next_state;                           

    //协商本地接收时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
    //协商本地发送时间            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;

    //更新检测时长
    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;

    //设置对端会话描述符
    if(bfd_session->bfdh.your_disc == 0)
        bfd_session->bfdh.your_disc = bfdh->my_disc;

    //收到Poll回复Final
    if(bfdh->poll) {
        old_poll_bit = bfd_session->bfdh.poll;
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        bfd_send_packet(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;       
    }

    //!Up状态发送默认时间配置
    bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
    bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);    
    
    bfd_session->act_tx_intv = 
        ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
        ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);

    bfd_session->act_rx_intv = 
        ntohl(bfd_session->bfdh.req_min_rx_intv) < ntohl(bfdh->des_min_tx_intv) ?
        ntohl(bfdh->des_min_tx_intv) : ntohl(bfd_session->bfdh.req_min_rx_intv);

    //重置发送定时器
    bfd_reset_tx_timer(bfd_session);

    //启动超时定时器
    bfd_reset_rx_timer(bfd_session);
    
    return 0;            
}


int bfd_fsm_down_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len) {
    int old_poll_bit;
    int old_state;
    int flag = 0;
    
    if(bfd_session->bfdh.my_disc != bfdh->your_disc)
        return -1;

    //状态变更 down -> up
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_INIT].next_state;                           

    //更新协商时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;

    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;

    //更新对端描述符
    if(bfd_session->bfdh.your_disc == 0)
        bfd_session->bfdh.your_disc = bfdh->my_disc;


    if(bfdh->final && bfd_session->bfdh.poll) {
        bfd_session->bfdh.poll = 0;
        //停止poll seq
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Finish. ",__FUNCTION__,__LINE__);
    
        //更新发送时间
        bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);
        
        bfd_session->act_rx_intv = 
            ntohl(bfd_session->bfdh.req_min_rx_intv) < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : ntohl(bfd_session->bfdh.req_min_rx_intv);

        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;      

        bfd_reset_tx_timer(bfd_session);
    }    
    
    if(bfd_session->bfdh.des_min_tx_intv != htonl(bfd_session->des_min_tx_time)){
        bfd_session->bfdh.poll = 1;
        bfd_log(&msg_buf[0], 512, "%s %d BFD  Start Poll Sequence . ",__FUNCTION__,__LINE__);
        flag = 1;
    }
    if(bfd_session->bfdh.req_min_rx_intv != htonl(bfd_session->req_min_rx_time)){
        bfd_session->bfdh.poll = 1;              
        if(!flag)
            bfd_log(&msg_buf[0], 512, "%s %d BFD  Start Poll Sequence . ",__FUNCTION__,__LINE__);
    }

    if(bfd_session->des_min_tx_time < ntohl(bfd_session->bfdh.des_min_tx_intv)) {
        if(bfd_session->des_min_tx_time > ntohl(bfdh->req_min_rx_intv)) {
            bfd_session->act_tx_intv = 
                bfd_session->des_min_tx_time < ntohl(bfdh->req_min_rx_intv) ?
                ntohl(bfdh->req_min_rx_intv) : bfd_session->des_min_tx_time;
            
            //增加判断，不一定重置定时器
            bfd_reset_tx_timer(bfd_session); 
        }
    }
    
    if(bfd_session->req_min_rx_time > ntohl(bfd_session->bfdh.req_min_rx_intv)){
        bfd_session->act_rx_intv = 
            bfd_session->req_min_rx_time < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->req_min_rx_time;
    }

    //Up状态下发送配置时间
    bfd_session->bfdh.des_min_tx_intv = htonl(bfd_session->des_min_tx_time);
    bfd_session->bfdh.req_min_rx_intv = htonl(bfd_session->req_min_rx_time);    
    
    if(bfdh->poll) {
        old_poll_bit = bfd_session->bfdh.poll;
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        bfd_send_packet(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;
    }


    bfd_reset_rx_timer(bfd_session);
    bfd_notify(bfd_session->key, "", BFDSessionUp);        

    return 0;
}


int bfd_fsm_down_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len) {
    return 0;
}


int bfd_fsm_down_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len) {                                 

  	return 0;
}


int bfd_fsm_down_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len) {
    return 0;
}


int bfd_fsm_init_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    return 0;
}

int bfd_fsm_init_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){

    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
        return -1;

    //记录对端发送时间和接收时间
    bfd_session->remote_req_rx_time = ntohl(bfdh->req_min_rx_intv);
    bfd_session->remote_req_tx_time = ntohl(bfdh->des_min_tx_intv);
    
    //更新协商时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;

    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;    

    //重置定时器             
    bfd_reset_rx_timer(bfd_session);
    return 0;
}

int bfd_fsm_init_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;
    int old_poll_bit;
    int flag = 0;    
    if(bfd_session->bfdh.my_disc != bfdh->your_disc)
        return -1;

    //记录对端发送时间和接收时间
    bfd_session->remote_req_rx_time = ntohl(bfdh->req_min_rx_intv);
    bfd_session->remote_req_tx_time = ntohl(bfdh->des_min_tx_intv);

    //状态变更 init --> up
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_INIT].next_state;                           

    //更新协商时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;

    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;

    if(bfdh->final && bfd_session->bfdh.poll) {
        bfd_session->bfdh.poll = 0;
        //停止poll seq
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Finish. ",__FUNCTION__,__LINE__);
    
        //更新发送时间
        bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);
    
        bfd_session->act_rx_intv = 
            ntohl(bfd_session->bfdh.req_min_rx_intv) < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : ntohl(bfd_session->bfdh.req_min_rx_intv);

        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;      

        bfd_reset_tx_timer(bfd_session);
    }        
    
    if(bfd_session->des_min_tx_time != ntohl(bfd_session->bfdh.des_min_tx_intv)){
        bfd_session->bfdh.poll = 1;
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Start. ",__FUNCTION__,__LINE__);
        flag = 1;
    }
    
    if(bfd_session->req_min_rx_time != ntohl(bfd_session->bfdh.req_min_rx_intv)){
        bfd_session->bfdh.poll = 1;
        if(!flag)
            bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Start. ",__FUNCTION__,__LINE__);
    }
    
    if(bfd_session->des_min_tx_time < ntohl(bfd_session->bfdh.des_min_tx_intv)) {
        if(bfd_session->act_tx_intv > ntohl(bfdh->req_min_rx_intv)){
            bfd_session->act_tx_intv = 
                bfd_session->des_min_tx_time < ntohl(bfdh->req_min_rx_intv) ?
                ntohl(bfdh->req_min_rx_intv) : bfd_session->des_min_tx_time;
            //增加判断，如果定时器参数变更才更改，否则不去操作定时器
            bfd_reset_tx_timer(bfd_session); 

        }            
    }

    if(bfd_session->req_min_rx_time > ntohl(bfd_session->bfdh.req_min_rx_intv)){
        bfd_session->act_rx_intv = 
            bfd_session->req_min_rx_time < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->req_min_rx_time;
        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;              
    }

    //Up状态下发送配置时间
	bfd_session->bfdh.des_min_tx_intv = htonl(bfd_session->des_min_tx_time);
	bfd_session->bfdh.req_min_rx_intv = htonl(bfd_session->req_min_rx_time);

    if(bfdh->poll) {
        old_poll_bit = bfd_session->bfdh.poll;
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        bfd_send_packet(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;
    }

    //重置超时定时器
    bfd_reset_rx_timer(bfd_session);
    bfd_notify(bfd_session->key, "", BFDSessionUp);

    return 0;
}

int bfd_fsm_init_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;
    int old_poll_bit;
    int flag = 0;
    
    if(bfd_session->bfdh.my_disc != bfdh->your_disc)
        return -1;

    //记录对端发送时间和接收时间
    bfd_session->remote_req_rx_time = ntohl(bfdh->req_min_rx_intv);
    bfd_session->remote_req_tx_time = ntohl(bfdh->des_min_tx_intv);

    //状态变更 init --> up
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_UP].next_state;                           

    //更新协商时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;
    
    //更新检测时长
    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;

    if(bfdh->final && bfd_session->bfdh.poll) {
        bfd_session->bfdh.poll = 0;
        //停止poll seq
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Finish. ",__FUNCTION__,__LINE__);
    
        //更新发送时间
        bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);
    
        bfd_session->act_rx_intv = 
            ntohl(bfd_session->bfdh.req_min_rx_intv) < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : ntohl(bfd_session->bfdh.req_min_rx_intv);

        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;      

        bfd_reset_tx_timer(bfd_session);
    }   


    if(bfd_session->des_min_tx_time != ntohl(bfd_session->bfdh.des_min_tx_intv)){
        bfd_session->bfdh.poll = 1;
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Start. ",__FUNCTION__,__LINE__);
        flag = 1;
    }
    
    if(bfd_session->req_min_rx_time != ntohl(bfd_session->bfdh.req_min_rx_intv)){
        bfd_session->bfdh.poll = 1;
        if(!flag)
            bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Start. ",__FUNCTION__,__LINE__);
    }
    
    if(bfd_session->des_min_tx_time < ntohl(bfd_session->bfdh.des_min_tx_intv)) {
        if(bfd_session->act_tx_intv > ntohl(bfdh->req_min_rx_intv)){
            bfd_session->act_tx_intv = 
                bfd_session->des_min_tx_time < ntohl(bfdh->req_min_rx_intv) ?
                ntohl(bfdh->req_min_rx_intv) : bfd_session->des_min_tx_time;
            //增加判断，如果定时器参数变更才更改，否则不去操作定时器
            bfd_reset_tx_timer(bfd_session); 

        }            
    }
    
    if(bfd_session->req_min_rx_time >= ntohl(bfd_session->bfdh.req_min_rx_intv)){
        bfd_session->act_rx_intv = 
            bfd_session->req_min_rx_time < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->req_min_rx_time;
        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;              
    }

    //Up状态下发送配置时间    
    bfd_session->bfdh.des_min_tx_intv = htonl(bfd_session->des_min_tx_time);
    bfd_session->bfdh.req_min_rx_intv = htonl(bfd_session->req_min_rx_time);
    
    if(bfdh->poll) {
        old_poll_bit = bfd_session->bfdh.poll;
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        bfd_send_packet(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;
    }        

    //reset_rx_timer
    bfd_reset_rx_timer(bfd_session);
    bfd_notify(bfd_session->key, "", BFDSessionUp);
    
    return 0;
}

int bfd_fsm_init_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;

    //状态变更 init --> down
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_TIMER_EXPIRE].next_state;   

    //更新诊断码
	bfd_session->bfdh.diag = BFD_DIAG_CTRL_TIME_EXPIRED;

    //重置对端会话描述符
	bfd_session->bfdh.your_disc = 0;

	//重置定时器
	bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
	bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);

    bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;
    bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;

    //重置发送定时器
    bfd_reset_tx_timer(bfd_session);

    //停止超时定时器 stop_rx_timer
    bfd_stop_rx_timer(bfd_session);

    return 0;
}

int bfd_fsm_init_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;
    
    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
        return -1;

    //状态变更      init --> admindown
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_ADMINDOWN].next_state;  

    //重置对端描述符
    bfd_session->bfdh.your_disc = 0;

    //更新诊断码
	bfd_session->bfdh.diag = BFD_DIAG_ADMIN_DOWN;

    //停止定时器
	bfd_stop_rx_timer(bfd_session);
	bfd_stop_tx_timer(bfd_session);

    //重置定时器
	bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
	bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);

    bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;
    bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;

	bfd_reset_tx_timer(bfd_session);
    
    return 0;
}

int bfd_fsm_up_rcvd_start(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    return 0;
}


int bfd_fsm_up_rcvd_down(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;
    
    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
        return -1;

    //状态变更 Up -> Down
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_DOWN].next_state;
    
    //重置诊断码
    bfd_session->bfdh.diag = BFD_DIAG_NBR_SESSION_DOWN;

    //重置对端描述符
    bfd_session->bfdh.your_disc = 0;

    //重置定时器
	bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
	bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);

    bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;
    bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;

    bfd_stop_rx_timer(bfd_session);
    bfd_reset_tx_timer(bfd_session);

    bfd_notify(bfd_session->key, "Neighbor Signaled Session Down", BFDSessionDown);
    return 0;
}

int bfd_fsm_up_rcvd_init(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_poll_bit;
    int old_state;
    
    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
        return -1;
        
    //更新协商时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;   

    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;        

    //收到final检查poll并更新时间
    if(bfdh->final && bfd_session->bfdh.poll) {
        bfd_session->bfdh.poll = 0;
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Finish. ",__FUNCTION__,__LINE__);
        //更新发送时间
        bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);
    
        bfd_session->act_rx_intv = 
            ntohl(bfd_session->bfdh.req_min_rx_intv) < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : ntohl(bfd_session->bfdh.req_min_rx_intv);

        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;      

        bfd_reset_tx_timer(bfd_session);
    }
    
    //收到poll发送final
    if(bfdh->poll) {
        old_poll_bit = bfd_session->bfdh.poll;
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        bfd_send_packet(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;
    }

    bfd_reset_rx_timer(bfd_session);
    
    return 0;

}

int bfd_fsm_up_rcvd_up(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_poll_bit;
    int old_state;
    
    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
        return -1;
        
    //更新协商时间
    bfd_session->act_rx_intv = 
            bfd_session->act_rx_intv < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : bfd_session->act_rx_intv;
            
    bfd_session->act_tx_intv = 
            bfd_session->act_tx_intv < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : bfd_session->act_tx_intv;

    bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;        


    //收到final检查poll
    if(bfdh->final && bfd_session->bfdh.poll) {
        bfd_session->bfdh.poll = 0;
        bfd_log(&msg_buf[0], 512, "%s %d BFD Poll Sequence Finish. ",__FUNCTION__,__LINE__);  
        //更新发送时间
        bfd_session->act_tx_intv = 
            ntohl(bfd_session->bfdh.des_min_tx_intv) < ntohl(bfdh->req_min_rx_intv) ?
            ntohl(bfdh->req_min_rx_intv) : ntohl(bfd_session->bfdh.des_min_tx_intv);
    
        bfd_session->act_rx_intv = 
            ntohl(bfd_session->bfdh.req_min_rx_intv) < ntohl(bfdh->des_min_tx_intv) ?
            ntohl(bfdh->des_min_tx_intv) : ntohl(bfd_session->bfdh.req_min_rx_intv);

        bfd_session->detect_time = bfdh->detect_mult * bfd_session->act_rx_intv;      

        bfd_reset_tx_timer(bfd_session);
    }

    //收到poll发送final
    if(bfdh->poll) {
        old_poll_bit = bfd_session->bfdh.poll;
        bfd_session->bfdh.poll = 0;
        bfd_session->bfdh.final = 1;
        bfd_send_packet(bfd_session);
        bfd_start_tx_timer(bfd_session);
        bfd_session->bfdh.final = 0;            
        bfd_session->bfdh.poll = old_poll_bit;
    }

    bfd_reset_rx_timer(bfd_session);
    
    return 0;
}

int bfd_fsm_up_rcvd_time_expire(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;

    //状态变更 Up --> Down
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_TIMER_EXPIRE].next_state;   

    //更新诊断码
	bfd_session->bfdh.diag = BFD_DIAG_CTRL_TIME_EXPIRED;

    //重置对端描述符
    bfd_session->bfdh.your_disc = 0;


	//重置定时器
	bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
	bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);

    bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;
    bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;

    //重置发送定时器
    bfd_reset_tx_timer(bfd_session);

    //停止超时定时器
    bfd_stop_rx_timer(bfd_session);

    bfd_notify(bfd_session->key, "Control Detection Time Expired", BFDSessionDown);
    return 0;
}

int bfd_fsm_up_rcvd_admindown(struct session *bfd_session, struct bfdhdr *bfdh, int recv_len){
    int old_state;
    
    if((bfdh->your_disc != 0) && (bfd_session->bfdh.my_disc != bfdh->your_disc))
       return -1;
       
    //状态变更
    old_state = bfd_session->bfdh.sta;
    bfd_session->bfdh.sta = FSM[bfd_session->bfdh.sta][BFD_EVENT_RECV_ADMINDOWN].next_state;  

    //重置对端描述符
    bfd_session->bfdh.your_disc = 0;

    //更新诊断码
	bfd_session->bfdh.diag = BFD_DIAG_ADMIN_DOWN;

    //停止定时器
	bfd_stop_rx_timer(bfd_session);
	bfd_stop_tx_timer(bfd_session);

    //重置定时器
	bfd_session->bfdh.des_min_tx_intv = htonl(BFD_DEFAULT_TX_INTERVAL);
	bfd_session->bfdh.req_min_rx_intv = htonl(BFD_DEFAULT_RX_INTERVAL);

    bfd_session->act_tx_intv = BFD_DEFAULT_TX_INTERVAL;
    bfd_session->act_rx_intv = BFD_DEFAULT_RX_INTERVAL;

	bfd_reset_tx_timer(bfd_session);
    bfd_notify(bfd_session->key, "Administratively Down", BFDSessionDown);
    return 0;
       
}


//bfd 状态机处理函数 
int bfd_fsm_event(struct session *bfd_session, int bfd_event, struct bfdhdr *bfdh, int recv_len) {
    int ret;
    #if 0
    switch(bfd_session->bfdh.sta){
        case BFD_STA_ADMINDOWN:
            bfd_log(msg_buf, BFD_MSG_BUFFER_SIZE , "%s:%d current sta : admindown",__FUNCTION__, __LINE__);
            break;

        case BFD_STA_DOWN:
            bfd_log(msg_buf, BFD_MSG_BUFFER_SIZE , "%s:%d current sta : down",__FUNCTION__, __LINE__);
            break;

        case BFD_STA_INIT:
            bfd_log(msg_buf, BFD_MSG_BUFFER_SIZE , "%s:%d current sta : init",__FUNCTION__, __LINE__);
            break;
            
        case BFD_STA_UP:
            bfd_log(msg_buf, BFD_MSG_BUFFER_SIZE , "%s:%d current sta : up",__FUNCTION__, __LINE__);
            break;
            
        default:
            bfd_log(msg_buf, BFD_MSG_BUFFER_SIZE , "%s:%d unrecognized sta",__FUNCTION__, __LINE__);
            return -1;
            break;        
    }
    #endif
	ret = (*(FSM[bfd_session->bfdh.sta][bfd_event].func))(bfd_session, bfdh, recv_len);

    return ret;   
}

//会话查找
struct session *bfd_session_lookup(uint32_t my_disc, struct sockaddr_in *dst, struct sockaddr_in * src) {
	int key;
	struct session *bfd_session = NULL;

	//加锁保护
    pthread_mutex_lock(&bfd_session_lock);
	if (my_disc){
		key = hash_key(my_disc, 0);
		if (key == -1) {
            pthread_mutex_unlock(&bfd_session_lock);		
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
		key = hash_key(0, dst->sin_addr.s_addr);
		if (key == -1) {
            pthread_mutex_unlock(&bfd_session_lock);		
            return NULL;
		}
		bfd_session = master.neigh_tbl[key];

        //对比地址
		while (bfd_session) {        		
			if (dst->sin_addr.s_addr == bfd_session->raddr.sin_addr.s_addr && src->sin_addr.s_addr == bfd_session->laddr.sin_addr.s_addr)
			    break;
			bfd_session = bfd_session->neigh_next;
		}
	}
    pthread_mutex_unlock(&bfd_session_lock);

    #if 0
	if (bfd_session == NULL && dst != 0)
        bfd_log(&msg_buf[0], 512, "%s %d addr not match, dst : %u:%u:%u:%u, raddr : %u:%u:%u:%u",__FUNCTION__,__LINE__, NIPQUAD(dst->sin_addr.s_addr),NIPQUAD(src->sin_addr.s_addr));             
    #endif
    
	return bfd_session;
}


//bfd报文合法性检查，合法返回0，非法返回-1           
int bfd_check_packet_validity(struct session *bfd_session, char *data, int recv_len, struct sockaddr_in *src) {
    struct bfdhdr *bfdh = NULL;
    
    bfdh = (struct bfdhdr *)data;

    //检查长度
    if(bfdh->len > recv_len) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d length is too short. Discarded. bfdh->len :%d > recv_len :%d",__FUNCTION__,__LINE__, bfdh->len, len);
        return -1;
    }
    
    if((!bfdh->auth && bfdh->len != BFD_CTRL_LEN) || (bfdh->auth && bfdh->len < BFD_CTRL_AUTH_LEN)) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d bfd packet length (%d) not right. Discarded ",__FUNCTION__,__LINE__, bfdh->len);
        return -1;
    }

    #if 0
    //检查地址，端口，NAT 
    if((bfd_session->raddr.sin_addr.s_addr != src->sin_addr.s_addr) || (bfd_session->raddr.sin_port != src->sin_port)) {
        return -1;
    }
    #endif 
    
    //判断版本号是否正确
    if(bfdh->version != BFD_VERSION) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d bfd packet wrong version : %u ",__FUNCTION__,__LINE__, bfdh->version);
        return -1;
    }

    //如果认证字段置位，discarded
    if(bfdh->auth) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d Auth type is set. Discarded",__FUNCTION__,__LINE__);
        return -1;
    }

    //检查是否同时设置了Poll & Final字段
    if(bfdh->poll && bfdh->final) {
        return -1;
    }

    //检查保留字段是否合法
    if(bfdh->mpoint != 0) {
        return -1;
    }
    
    //检查detect_mult是否合法
    if(bfdh->detect_mult == 0) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d Detect Multi field is zero. Discarded ",__FUNCTION__,__LINE__);
        return -1;
    }

    //检查 my_disc是否合法
    if(bfdh->my_disc == 0) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d My Discriminator field is zero. Discarded ",__FUNCTION__,__LINE__);
        return -1;
    }

    //检测echo字段是否合法        
    if (bfdh->req_min_echo_rx_intv != 0) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d echo_rx_intv not zero, Discarded, peer_req_echo_rx_intv : %x ",__FUNCTION__,__LINE__, bfdh->req_min_echo_rx_intv);
        return -1;
    }

    //查询模式，discarded
    if(bfdh->demand) {
        //bfd_log(&msg_buf[0], 512, "[BFD] %s %d receive demand mode set, discarded ",__FUNCTION__,__LINE__);
        return -1;
    }

    //检查your_disc & sta
    if(!bfdh->your_disc && (bfdh->sta != BFD_STA_DOWN)) {
        return -1;      
    }

    return 0;    
}


//bfd会话线程 
void *bfd_session_work(void *data) {
    int ret;
    int err = 0;
    int is_quit = 0;
    int test = 0;
    
    char buffer[BUFF_SIZE] = {0};
    char msg_buffer[BFD_MSG_BUFFER_SIZE] = {0};    
    struct bfdhdr *bfdh = NULL;
    struct msg_node *msg = NULL;
    struct msg_node *msg1 = NULL;
    struct session *bfd_session = NULL;     
    int recv_len, addr_len;
    struct sockaddr_in src;
    
    addr_len = sizeof(struct sockaddr_in);
    bfd_session = (struct session *)data;

    
    //循环监听消息队列
    while(!is_quit) {  
        pthread_mutex_lock(&bfd_session->bfd_mutex);
        
        while(bfd_session->msg_head == NULL)   
            pthread_cond_wait(&bfd_session->bfd_cond, &bfd_session->bfd_mutex);            

        msg = bfd_session->msg_head;
        bfd_session->msg_head = bfd_session->msg_head->next;        

        pthread_mutex_unlock(&bfd_session->bfd_mutex);                    

        switch (msg->msg_type){
            //超时发送事件
            case MSG_EVENT_TX_TIMER:
                //bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d tx timer",__FUNCTION__, __LINE__);

                bfd_send_packet(bfd_session);
                bfd_start_tx_timer(bfd_session);

                break;

            //超时接收事件    
            case MSG_EVENT_RX_TIMER:
                //bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d rx timer",__FUNCTION__, __LINE__);            
                bfd_fsm_event(bfd_session, BFD_EVENT_TIMER_EXPIRE, NULL, 0);

                break;

            //报文读取接收事件
            case MSG_EVENT_SOCKET:
                err = 0;
                //bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d receive socket",__FUNCTION__, __LINE__);                                                
                //recv_len = recvfrom(bfd_session->sockfd.fd, buffer, BUFF_SIZE, MSG_DONTWAIT, (struct sockaddr *)&src, &addr_len);
                //bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d receive, recv_len : %d, errno: %d",__FUNCTION__, __LINE__, recv_len, errno);                
                recv_len = recvfrom(bfd_session->sockfd.fd, buffer, BUFF_SIZE, 0, (struct sockaddr *)&src, &addr_len);
                
                if(recv_len >= BFD_CTRL_LEN) {                
                    err = bfd_check_packet_validity(bfd_session, buffer, recv_len, &src);

                    //状态机处理
                    if(!err) {
                        bfdh = (struct bfdhdr *)buffer;
                        switch(bfdh->sta){                            
                            case BFD_STA_ADMINDOWN:

                                bfd_fsm_event(bfd_session, BFD_EVENT_RECV_ADMINDOWN, bfdh, recv_len);
                                break;
                        
                            case BFD_STA_DOWN:

                                bfd_fsm_event(bfd_session, BFD_EVENT_RECV_DOWN, bfdh, recv_len);
                                break;
                        
                            case BFD_STA_INIT:
                                bfd_fsm_event(bfd_session, BFD_EVENT_RECV_INIT, bfdh, recv_len);
                        
                                break;
                        
                            case BFD_STA_UP:
                                bfd_fsm_event(bfd_session, BFD_EVENT_RECV_UP, bfdh, recv_len);

                                break;
                        
                            default:
                                break;                            
                        }
                    }
                }

                break;

            //删除事件    
            case MSG_EVENT_DELETE:
                //发送admindown报文
                bfd_session->bfdh.sta = BFD_STA_ADMINDOWN;
                bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d send admindown",__FUNCTION__, __LINE__);                
                bfd_send_packet(bfd_session);
                
                //从epoll队列中删除
                epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->rx_timer.fd, NULL);      
                epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->tx_timer.fd, NULL);      
                epoll_ctl(efd, EPOLL_CTL_DEL, bfd_session->sockfd.fd, NULL);      

                //停止定时器
                bfd_stop_tx_timer(bfd_session);
                bfd_stop_rx_timer(bfd_session);
                
                //关闭定时器描述符
                close(bfd_session->rx_timer.fd);
                close(bfd_session->tx_timer.fd);
                close(bfd_session->sockfd.fd);

                //释放消息队列
                pthread_mutex_lock(&bfd_session->bfd_mutex);
                while(bfd_session->msg_head != NULL) {
                    msg1 = bfd_session->msg_head;
                    bfd_session->msg_head = msg1->next;
                    free(msg1);
                    msg1 = NULL;
                }                
                pthread_mutex_unlock(&bfd_session->bfd_mutex); 

                is_quit = 1;                
                break;

            //初始事件
            case MSG_EVENT_START:
                bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d start event",__FUNCTION__, __LINE__);            
                bfd_fsm_event(bfd_session, BFD_EVENT_START, NULL, 0);    

                break;

            default:
                bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d unrecognized event",__FUNCTION__, __LINE__);                        
                break;
        }                                                       
        free(msg);
        msg = NULL;
    }

    //释放线程资源
    pthread_mutex_destroy(&bfd_session->bfd_mutex);
    pthread_cond_destroy(&bfd_session->bfd_cond);
    
    free(bfd_session);
    bfd_log(msg_buffer, BFD_MSG_BUFFER_SIZE , "%s:%d bfd session close success",__FUNCTION__, __LINE__);                        
    return NULL;
}


//epoll工作函数, 监听epoll事件并发送消息到响应控制块的消息队列 
void *bfd_epoll_work(void *data) {
    int i;
    int ret, fds;
    uint64_t value;
    char epoll_msg[BFD_MSG_BUFFER_SIZE] = {0}; 
    struct msg_node *msg = NULL;
    struct msg_node *msg_priv = NULL;
    struct epoll_callback_data *event_data = NULL;

    //设置允许线程取消
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

    //设置延迟取消
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    while(1) {
        // 设置线程取消点
        pthread_testcancel(); 
        fds = epoll_wait(efd, g_events, BFD_SESSION_HASH_SIZE, -1);
        for (i = 0; i<fds; i++) {    
            msg = NULL;
            event_data = (struct epoll_callback_data *)g_events[i].data.ptr;
            if (g_events[i].events & EPOLLIN) { 
                switch (event_data->fd_type) {
                    //发送消息
                    case MSG_EVENT_TX_TIMER : 
                        //bfd_log(epoll_msg, sizeof(epoll_msg), "%s:%d epoll tx event type",__FUNCTION__, __LINE__);                                        
                        ret = read(event_data->fd, &value, sizeof(uint64_t));
                        if(ret != -1){
                              //创建消息节点
                              msg = calloc(1, sizeof(struct msg_node));
                              if(msg == NULL)
                                  break;
                              msg->next = NULL;
                              msg->msg_type = MSG_EVENT_TX_TIMER;
                              pthread_mutex_lock(&(event_data->bfd_session->bfd_mutex));    
                              //追加消息节点
                              if (event_data->bfd_session->msg_head == NULL)
                                  event_data->bfd_session->msg_head = msg;
                              else {
                                  msg_priv = event_data->bfd_session->msg_head;
                                  while(1) {
                                      if (msg_priv->next != NULL)
                                          msg_priv = msg_priv->next;
                                      else {
                                          msg_priv->next = msg;
                                          break;
                                      }
                                  }
                              }                           
                              pthread_mutex_unlock(&(event_data->bfd_session->bfd_mutex));         
                            
                              //通知消费者线程
                              pthread_cond_signal(&(event_data->bfd_session->bfd_cond));  
                            //  bfd_log(&epoll_msg[0], sizeof(epoll_msg), "%s:%d epoll tx event ",__FUNCTION__, __LINE__);                            
                        }

                        break;

                    //超时消息
                    case MSG_EVENT_RX_TIMER :
                        //bfd_log(epoll_msg, sizeof(epoll_msg), "%s:%d epoll rx event type",__FUNCTION__, __LINE__);                                        

                        ret = read(event_data->fd, &value, sizeof(uint64_t));
                        if(ret != -1){
                            //创建消息节点
                            msg = calloc(1, sizeof(struct msg_node));
                            if(msg == NULL)
                                break;
                            msg->next = NULL;
                            msg->msg_type = MSG_EVENT_RX_TIMER;
                            pthread_mutex_lock(&(event_data->bfd_session->bfd_mutex));
                            
                            //追加消息节点                     
                            if (event_data->bfd_session->msg_head == NULL)
                                event_data->bfd_session->msg_head = msg;
                            else {
                                msg_priv = event_data->bfd_session->msg_head;
                                while(1) {
                                    if (msg_priv->next != NULL)
                                        msg_priv = msg_priv->next;
                                    else {
                                        msg_priv->next = msg;
                                        break;
                                    }
                                }
                            }    
                            
                            pthread_mutex_unlock(&(event_data->bfd_session->bfd_mutex));         
                            
                            //通知消费者线程
                            pthread_cond_signal(&(event_data->bfd_session->bfd_cond));  
                            //bfd_log(&epoll_msg[0], sizeof(epoll_msg), "%s:%d epoll rx event ",__FUNCTION__, __LINE__);
                        }

                        break;

                    //套接字消息
                    case MSG_EVENT_SOCKET :
                        //bfd_log(epoll_msg, sizeof(epoll_msg), "%s:%d epoll receive event type",__FUNCTION__, __LINE__);                                      
                        //创建消息节点                        
                        msg = calloc(1, sizeof(struct msg_node));
                        if(msg == NULL)
                            break;
                        msg->next = NULL;
                        msg->msg_type = MSG_EVENT_SOCKET;
                        
                        pthread_mutex_lock(&(event_data->bfd_session->bfd_mutex));
    
                        //追加消息节点                     
                        if (event_data->bfd_session->msg_head == NULL)
                            event_data->bfd_session->msg_head = msg;
                        else {
                            msg_priv = event_data->bfd_session->msg_head;
                            while(1) {
                                if (msg_priv->next != NULL)
                                    msg_priv = msg_priv->next;
                                else{
                                    msg_priv->next = msg;
                                    break ;
                                }                                    
                            }
                        }                            
                        pthread_mutex_unlock(&(event_data->bfd_session->bfd_mutex));         

                        //通知消费者线程
                        pthread_cond_signal(&(event_data->bfd_session->bfd_cond));	
                        //bfd_log(&epoll_msg[0], sizeof(epoll_msg), "%s:%d epoll socket event ",__FUNCTION__, __LINE__);

                        break;
                        
                    default:
                        bfd_log(epoll_msg, sizeof(epoll_msg), "%s:%d unrecognized epoll event type",__FUNCTION__, __LINE__);                    
                        break;                        
                }
            }            
        }        
    }
    
    return NULL;    

}


//设置回调函数
void bfd_setCallback(CALLBACK_FUNC pfunc) {
    callbackSendMsg = pfunc;	
}


//设置回调函数
void bfd_setLogCallback(LOG_CALLBACK_FUNC pfunc) {
    log_callback = pfunc;	
}


//发送信息
void bfd_notify(char *msgkey, char *msginfo, int msgtype) {
    BFD_RSP rsp;
    strncpy(rsp.msgkey, msgkey, 56);
    strncpy(rsp.msginfo, msginfo, 56);
    rsp.msgtype = msgtype;

    callbackSendMsg(&rsp);

    return ;
}


//打印日志
void bfd_log(char *msg, int size, const char *fmt, ...) {   
    va_list ap;    
    //将消息缓存置零
    memset(msg, 0, size);   
    va_start(ap, fmt);
    //写入消息
    vsnprintf(msg, size, fmt, ap);
    va_end(ap);

    //调用go log函数
    log_callback(msg);
    
    return ;
}


//配置参数打印
void bfd_session_cfg_dump(struct session_cfg *session_cfg) {
    return ;
    bfd_log(&msg_buf[0], 512,"%s:%d local_ip_type : %u "
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

//删除bfd会话
void bfd_delete(BFD_CFG *cfg){
	int ret = 0;
    unsigned int key;
    struct session_cfg  val;
	struct sockaddr_in src, dst;
    struct session *bfd_session = NULL;
    struct msg_node *msg = NULL;
    struct msg_node *msg_priv = NULL;
    
    struct session *neigh_cur = NULL;
    struct session *neigh_priv = NULL;
    struct session *session_cur = NULL;
    struct session *session_priv = NULL;

	src.sin_addr.s_addr = inet_addr(cfg->localIP);
    src.sin_port = htons(cfg->localPort);
	dst.sin_addr.s_addr = inet_addr(cfg->remoteIP);
    dst.sin_port = htons(cfg->remotePort);    
	
    val.local_port = cfg->localPort;                //本地端口
    val.remote_port = cfg->remotePort;              //远端端口
    val.local_ip.ip = inet_addr(cfg->localIP);                          //本地IP地址
    val.remote_ip.ip = inet_addr(cfg->remoteIP);                         //远端IP地址
    strncpy(val.key, cfg->key, 55);                 //key值
    bfd_session_cfg_dump(&val);

    bfd_session = bfd_session_lookup(0, &dst, &src);
    
    if(bfd_session) {
        //从会话队列中移除会话
        pthread_mutex_lock(&bfd_session_lock); 
        key = hash_key(bfd_session->bfdh.my_disc, 0);
        session_cur = master.session_tbl[key];
        
        while(session_cur && session_cur->bfdh.my_disc != bfd_session->bfdh.my_disc) {
            session_priv = session_cur;
            session_cur = session_cur->session_next;
        }
        
        if (session_priv == NULL)
            master.session_tbl[key] = session_cur->session_next;
        else 
            session_priv->session_next = session_cur->session_next; 
        
        key = hash_key(0, bfd_session->raddr.sin_addr.s_addr);
        neigh_cur = master.neigh_tbl[key];
        while(neigh_cur && neigh_cur->bfdh.my_disc != bfd_session->bfdh.my_disc) {
            neigh_priv = neigh_cur;
            neigh_cur = neigh_cur->neigh_next;
        }
        
        if (neigh_priv == NULL)
            master.neigh_tbl[key] = neigh_cur->neigh_next;
        else 
            neigh_priv->neigh_next = neigh_cur->neigh_next;
            
        pthread_mutex_unlock(&bfd_session_lock);    

        //创建消息节点并发送初始会话消息
        msg = calloc(1, sizeof(struct msg_node));
        if(msg) {
            msg->next = NULL;
            msg->msg_type = MSG_EVENT_DELETE;
            pthread_mutex_lock(&(bfd_session->bfd_mutex));
        
            //追加消息节点
            if (bfd_session->msg_head == NULL)
                bfd_session->msg_head = msg;
            else {
                msg_priv = bfd_session->msg_head;
                while(1) {
                    if (msg_priv->next != NULL)
                        msg_priv = msg_priv->next;
                    else {
                        msg_priv->next = msg;
                        break;
                    }                
                }
            }              
            pthread_mutex_unlock(&(bfd_session->bfd_mutex));         
            pthread_cond_signal(&(bfd_session->bfd_cond));  
        }   
    }
    
	return;
}


//添加bfd配置
void bfd_add(BFD_CFG *cfg) {
	uint32_t src, dst;
	int ret = 0;
	src = inet_addr(cfg->localIP);
	dst = inet_addr(cfg->remoteIP);

    struct session_cfg  val;
    val.local_ip_type = cfg->localIPType;           //本地ip类型
    val.local_port = cfg->localPort;                //本地端口
    val.remote_ip_type = cfg->remoteIPType;         //远端ip类型
    val.remote_port = cfg->remotePort;              //远端端口
    val.detect_multi = cfg->detectMult;             //检测次数
    val.des_min_tx_interval = cfg->desMinTx * 1000; //默认发送时长
    val.req_min_rx_interval = cfg->reqMinRx * 1000; //默认超时时长
    val.req_min_echo_rx = cfg->reqMinEchoRx;        //默认echo报文时长
    val.local_ip.ip = src;                          //本地IP地址
    val.remote_ip.ip = dst;                         //远端IP地址
    //val.service_type = cfg->serviceType;
    strncpy(val.key, cfg->key, 55);                 //key值
    bfd_session_cfg_dump(&val);

    ret = bfd_session_add(&val);
    #if 0
    if (ret != 0) {
      //  bfd_notify(val.key, "bfd add session fail", HaBFDSessionCreateFailRsp);
    }
    #endif
    
    return ;    
}


//bfd初始化，成功返回0
int bfd_init(void) {
    int ret;   

    //创建 efd 文件描述
    efd = epoll_create1(0);
    if (efd == -1) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), " %s:%d create epoll fail ",__FUNCTION__, __LINE__);
        return -1;
    }
    bfd_log(&msg_buf[0], sizeof(msg_buf), " %s:%d create epoll instance success ",__FUNCTION__, __LINE__);    
    
    g_events = (struct epoll_event *)calloc(BFD_SESSION_HASH_SIZE, sizeof(struct epoll_event));
    if(g_events == NULL) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), " %s:%d epoll event cache calloc fail ",__FUNCTION__, __LINE__);
        close(efd);
        return -1;
    }
    
    //会话表初始化
    memset(&master, 0, sizeof(struct bfd_master));      
    
    //创建接收线程
    ret = pthread_create(&epoll_thread, NULL, bfd_epoll_work, NULL);
    if (ret != 0 ) {
        bfd_log(&msg_buf[0], sizeof(msg_buf), " %s:%d thread create fail ",__FUNCTION__, __LINE__);   
        goto err1;
    }
    bfd_log(&msg_buf[0], sizeof(msg_buf), "%s:%d epoll thread create success ",__FUNCTION__, __LINE__);       

    return 0;   
    
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
    struct msg_node *msg = NULL;
    struct msg_node *msg_priv = NULL;
    struct session *bfd_session = NULL;
    struct session *session_next = NULL;
    struct session *neigh = NULL;
    struct session *neigh_priv = NULL;

    // 释放bfd会话
    pthread_mutex_lock(&bfd_session_lock);
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

            //创建消息节点并发送初始会话消息
            msg = calloc(1, sizeof(struct msg_node));
            if(msg) {
                msg->next = NULL;
                msg->msg_type = MSG_EVENT_DELETE;
                pthread_mutex_lock(&(bfd_session->bfd_mutex));
        
                //追加消息节点
                if (bfd_session->msg_head == NULL)
                    bfd_session->msg_head = msg;
                else {
                    msg_priv = bfd_session->msg_head;
                    while(1) {
                        if (msg_priv->next != NULL)
                            msg_priv = msg_priv->next;
                        else {
                            msg_priv->next = msg;
                            break;
                        }                
                    }
                }              
                
                pthread_mutex_unlock(&(bfd_session->bfd_mutex));         
                pthread_cond_signal(&(bfd_session->bfd_cond));  
            }            
            bfd_session = master.session_tbl[i];
       }       
    }
    pthread_mutex_unlock(&bfd_session_lock);

    // 通知线程退出    
    pthread_cancel(epoll_thread);
    pthread_join(epoll_thread, NULL);     
    bfd_log(&msg_buf[0], sizeof(msg_buf), "%s:%d bfd epoll_thread exit",__FUNCTION__, __LINE__);

    // 关闭文件描述
    close(efd);
    if (g_events) {
        free(g_events);
        g_events = NULL;
    }
    
    return ret;
}

