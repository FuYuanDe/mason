/*
 *	Linux NET3:	xrtp relay decoder.
 *
 *	Authors: Kyle <zx_feng807@foxmail.com>
 *
 */
 

#include <linux/module.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/errno.h>
#include <linux/in.h>
#include <linux/mm.h>
#include <linux/inet.h>
#include <linux/inetdevice.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/fddidevice.h>
#include <linux/if_arp.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/stat.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/time.h>
#ifdef CONFIG_SYSCTL
#include <linux/sysctl.h>
#endif

#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/icmp.h>
#include <net/route.h>
#include <net/protocol.h>
#include <net/tcp.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/ax25.h>
#include <net/netrom.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/netfilter_ipv6.h>

#include <linux/kdev_t.h>
#include <linux/cdev.h>

#include <net/dsfield.h>
#include <linux/if_vlan.h>

#include <linux/netfilter_bridge/ebtables.h>
#include <linux/if_bridge.h>

#include <linux/list.h>
#include <linux/sched.h>   //wake_up_process()
#include <linux/kthread.h> //kthread_create()��kthread_run()
#include <linux/err.h>           //IS_ERR()��PTR_ERR()2.ʵ�֣�kthread_create ��kthread_run����

#include <linux/init.h>
#include <linux/workqueue.h>
#include <linux/hrtimer.h>

#include "xrtp_rm.h"
#include "xrtp_relay.h"
#include "xrtp_rtcp.h"


#define RTP_DRIVER_VERSION            "0.2.12"

//#define RTP_DSP_TEST_MODE 1

#define RTP_DRIVER_PKT_DISPATCH     1
//#define RTP_DYNAMIC_DISPATCH_CPU    1

#define RTP_DPS_MULTI_SOCKET        0

/* ��������50�����ļ�����ý���� */
#define RTP_MEDIA_LOCK_PKTS         50

#define RTP_HZ  1000

#define RTP_DSP_CHAN_MAX            512
#define RTP_DSP_CHAN_MASK           0x1ff   /* 512 - 1 */
#define RTP_DSP_CHAN_DIR_ORIGINAL   1       /* original ���� */
#define RTP_DSP_CHAN_DIR_REPLY      2       /* reply ���� */

static unsigned int g_rtp_hz_ticks = 1000;
static unsigned int g_master_solt_id = 0;   /* ��ǰ���ذ��λ�� */
static unsigned char g_dtsl_redirect_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0xFF, 0x01};
static unsigned char g_broadcast_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

static struct kmem_cache *g_rtp_cachep = NULL;
static struct rtp_ctrl_tbl *g_rtp_ctrl_tbl[2] = {NULL};   /* 0�±����udp, 1�±����tcp */
static struct rtp_dsp_entry g_rtp_dsp_chan_entry[RTP_DSP_CHAN_MAX];

static struct sock *rtp_nfnl = NULL;
static struct ctl_table_header *g_rtp_sysctl_header = NULL;  

/* ʹ��cpuת������ */
static int core_cpu_nums = 0;
module_param(core_cpu_nums, int, 0444);
/* ʹ��cpuת����ʼid */
static int core_cpu_base = 0;
module_param(core_cpu_base, int, 0444);
static unsigned int g_rtp_port_min = 0;
static unsigned int g_rtp_port_max = 65535;

static unsigned int g_rtp_log_enable = 0;
static unsigned int g_debug_enable = 0;
static unsigned int g_dsp_test_mode = 1;
static unsigned int g_rtp_user_pid = 0;
static unsigned int g_rtp_user_notify_pid = 0;
static unsigned int g_rtp_conns_count = 0;
static unsigned int g_rtp_dsp_conns_count = 0;
static unsigned int g_rtp_check_enable = 1;
static unsigned int g_debug_conn_enable = 0;
static unsigned int g_rtp_vlan_all_untag = 1;
static int          g_rtp_qos_pkts_power = 2;
static unsigned int g_rtp_qos_audio_pkts_count = 200;
static unsigned int g_rtp_qos_video_pkts_count = 10000;
static unsigned int g_rtp_qos_image_pkts_count = 10000;

static __be32 g_loopback_addr;
static struct dst_entry	*g_loopback_dst_entry = NULL;
//static struct net_device *g_dev_eth0 = NULL;
//static struct net_device *g_dev_loopback = NULL;

static struct timer_list g_rtp_rate_ticktimer;
/* ÿ����ͳ��һ�� */
static unsigned int g_rtp_rate_timeval = 60;
/* ��ĳһ������������һ���÷�ֵʱ(ȱʡΪ30KB/sec,���711����10KB/sec)���澯���� */
static unsigned int g_rtp_flow_max_rate = 30 * 1024;

static unsigned int g_rtp_media_lock_pkts = RTP_MEDIA_LOCK_PKTS;

static atomic_t g_rtp_atomic_conns_count;

/* rtp packet delay status */
static unsigned int g_rtp_delay_enable = 0;
static unsigned int g_rtp_delay_pkt_enable = 0;
static unsigned int g_rtp_delay_times = 2;
module_param(g_rtp_delay_enable, int, 0444);
module_param(g_rtp_delay_pkt_enable, int, 0444);
module_param(g_rtp_delay_times, int, 0444);

/* begin for rtp relay jitter buffer */
#define RTP_JITTER_BUFFER           1   /* ����jitter buffer���� */
//#define RTP_JITTER_KTHREAD          1   /* ʹ���ں��̷߳��Ͷ��а� */
#define RTP_JITTER_WORK_QUEUE       1   /* ʹ�ù�������ʵ�ַ��Ͷ��а� */
#define RTP_JITTER_BUFFER_HRTIMER   1   /* ʹ�ø߾��ȶ�ʱ�� */

#define RTP_JITTER_BUFFER_PKTS      64  /* ÿ��ͨ����󻺴������ */

struct rtp_skb_cache {
    struct sk_buff   *skb;
    struct list_head list;
};

struct rtp_skb_cache_ctrl {
    struct list_head cache_head;    /* ��ǰ���汨������ */
    struct list_head list_free;     /* ���л������� */
    unsigned int input_cnt;         /* ���н��ձ������� */
    unsigned int output_cnt;        /* ���з��ͱ������� */
    unsigned int used_cnt;          /* ���е�ǰ���汨���� */
    unsigned int packet_time;       /* ͨ�����ʱ�� */
    unsigned int used_max;          /* ĳһʱ����󻺴汨���� */
    unsigned int overflow;          /* ���б�������� */
    spinlock_t lock;
};

#ifdef RTP_JITTER_KTHREAD
static struct task_struct *g_jitter_buffer_task = NULL;
#endif
#ifdef RTP_JITTER_WORK_QUEUE
static struct workqueue_struct *g_jitter_buffer_wqueue = NULL;
static struct work_struct       g_jitter_buffer_work;
#endif

static struct rtp_skb_cache *g_rtp_skb_cache_buffer = NULL;

/* �Ƿ�ʼ�ں�ת��jitter buffer���� */
static int g_jitter_buffer_enable = 0;
/* �ں��̷߳��ͱ������ڣ�ȱʡ1��tick */
static int g_jitter_buffer_ticks = 1;
/* �ں��߳�ÿ������ÿ��dspͨ������ͱ����� */
static int g_jitter_buffer_size = 1;
/* �ں˶�����󻺴���� */
static int g_jitter_buffer_max = 32;
/* �ں�hrtimer��ʱ��ʱ����(ms),ȱʡΪ10���� */
static unsigned int g_jigger_buffer_times_ms = 10;

static struct rtp_skb_cache_ctrl *g_jitter_buffer_ctrl = NULL;

static struct hrtimer g_jitter_buffer_hrtimer;
//static ktime_t g_jitter_buffer_kt;

/* ת���潫���ļ���jitter buffer������� */
static int rtp_relay_jitter_buffer_add(struct sk_buff *skb, int chan_id)
{
    struct rtp_skb_cache *entry, *n;
    
    spin_lock_bh(&g_jitter_buffer_ctrl[chan_id].lock);

    if (g_jitter_buffer_ctrl[chan_id].used_cnt >= g_jitter_buffer_max)
    {
        /* ������ǰ���Ļ������ */
        spin_unlock_bh(&g_jitter_buffer_ctrl[chan_id].lock);
        return -1;
    }
   
    list_for_each_entry_safe(entry, n, &g_jitter_buffer_ctrl[chan_id].list_free, list)
    {   
        list_del(&entry->list);

        entry->skb = skb;
        list_add_tail(&entry->list, &g_jitter_buffer_ctrl[chan_id].cache_head);
        g_jitter_buffer_ctrl[chan_id].input_cnt++;
        g_jitter_buffer_ctrl[chan_id].used_cnt++;

        /* ��¼��󻺴���� */
        if (g_jitter_buffer_ctrl[chan_id].used_cnt > g_jitter_buffer_ctrl[chan_id].used_max)
        {
            g_jitter_buffer_ctrl[chan_id].used_max = g_jitter_buffer_ctrl[chan_id].used_cnt;
        }

        spin_unlock_bh(&g_jitter_buffer_ctrl[chan_id].lock);
        return 0;
    }
    /* ���Ķ��������ͳ�� */
    g_jitter_buffer_ctrl[chan_id].overflow++;
    
    spin_unlock_bh(&g_jitter_buffer_ctrl[chan_id].lock);
    return -1;
}

/* skb������з��ͳ������� */
static void rtp_relay_jitter_buffer_tx(void *data)
{
    int i, k;
    struct rtp_skb_cache *entry;
    int cycle_cache_size;
    struct sk_buff *skb_cache;
    
    if (g_debug_enable == 88)
    {
        ktime_t	tstamp = ktime_get_real();
        hook_debug("hrtimer start timestamp:%lld \n", ktime_to_ms(tstamp));
    }

    /* ���Ͷ��а����ڵ���Ϊ�����Ӷ�Ϊ��λ(chan ��) */
    for (i = 0; i < RTP_DSP_CHAN_MAX/2; i++)
    {
        for (cycle_cache_size = g_jitter_buffer_size; cycle_cache_size > 0; cycle_cache_size--)
        {
            spin_lock_bh(&g_jitter_buffer_ctrl[i].lock);
            if (!list_empty(&g_jitter_buffer_ctrl[i].cache_head))
            {
                entry = list_first_entry(&g_jitter_buffer_ctrl[i].cache_head, struct rtp_skb_cache, list);
                list_del(&entry->list);
                skb_cache = entry->skb;
                entry->skb = NULL;
                list_add(&entry->list, &g_jitter_buffer_ctrl[i].list_free);
                g_jitter_buffer_ctrl[i].output_cnt++;
                g_jitter_buffer_ctrl[i].used_cnt--;
                spin_unlock_bh(&g_jitter_buffer_ctrl[i].lock);

                if (skb_cache)
                {
                    ip_local_out(skb_cache);
                }

                continue;
            }
            spin_unlock_bh(&g_jitter_buffer_ctrl[i].lock);
            break;
        }

        k = i + RTP_DSP_CHAN_MAX/2;
        for (cycle_cache_size = g_jitter_buffer_size; cycle_cache_size > 0; cycle_cache_size--)
        {
            spin_lock_bh(&g_jitter_buffer_ctrl[k].lock);
            if (!list_empty(&g_jitter_buffer_ctrl[k].cache_head))
            {
                entry = list_first_entry(&g_jitter_buffer_ctrl[k].cache_head, struct rtp_skb_cache, list);
                list_del(&entry->list);
                skb_cache = entry->skb;
                entry->skb = NULL;
                list_add(&entry->list, &g_jitter_buffer_ctrl[k].list_free);
                g_jitter_buffer_ctrl[k].output_cnt++;
                g_jitter_buffer_ctrl[k].used_cnt--;
                spin_unlock_bh(&g_jitter_buffer_ctrl[k].lock);

                if (skb_cache)
                {
                    ip_local_out(skb_cache);
                }

                continue;
            }
            spin_unlock_bh(&g_jitter_buffer_ctrl[k].lock);
            break;
        }
    }

    return;
}

#ifdef RTP_JITTER_KTHREAD
/* �̴߳������ */
static int rtp_relay_jitter_buffer_kthread_func(void *data)
{
    for(;;)
    {
        set_current_state(TASK_UNINTERRUPTIBLE);
        if (kthread_should_stop())
        {
            break;
        }

        rtp_relay_jitter_buffer_tx(NULL);
        
        
        /* 1 ticks = 10ms */
        schedule_timeout(g_jitter_buffer_ticks);
    }

    return 0;
}
#endif

#ifdef RTP_JITTER_BUFFER_HRTIMER
/* �߾��ȶ�ʱ��������� */
static enum hrtimer_restart rtp_vibrator_hrtimer_func(struct hrtimer *timer)
{
    if (g_jitter_buffer_enable)
    {
        queue_work(g_jitter_buffer_wqueue, &g_jitter_buffer_work);
    }
    
    /* send signal */
    hrtimer_forward_now(&g_jitter_buffer_hrtimer, ktime_set(0, MS_TO_NS(g_jigger_buffer_times_ms)));

    return HRTIMER_RESTART;
}

/* �߾��ȶ�ʱ�ĳ�ʼ�� */
static void rtp_relay_jitter_buffer_hrtimer_init(void)
{
    hook_info("rtp jitter buffer httimer init. \n");
    
    hrtimer_init(&g_jitter_buffer_hrtimer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    g_jitter_buffer_hrtimer.function = rtp_vibrator_hrtimer_func;
    hrtimer_start(&g_jitter_buffer_hrtimer, ktime_set(0, MS_TO_NS(g_jigger_buffer_times_ms)), HRTIMER_MODE_REL_PINNED);

    return;
}

/* �߾��ȶ�ʱ�����ע�� */
static void rtp_relay_jitter_buffer_hrtimer_fini(void)
{
    hrtimer_cancel(&g_jitter_buffer_hrtimer);
    
    return;
}
#endif

/* rtp�ں�ת��jitter buffer���ܳ�ʼ�� */
static int rtp_relay_jitter_buffer_init(void)
{
    int err, i, j;

    hook_info("rtp jitter buffer init. \n");

    g_rtp_skb_cache_buffer = (struct rtp_skb_cache *)kmalloc((sizeof(struct rtp_skb_cache) * RTP_JITTER_BUFFER_PKTS * RTP_DSP_CHAN_MAX), GFP_KERNEL);
    if (!g_rtp_skb_cache_buffer)
    {
        hook_info("kmalloc rtp_skb_cache_buffer fail. \n");
        return -1;
    }

    g_jitter_buffer_ctrl = (struct rtp_skb_cache_ctrl *)kmalloc((sizeof(struct rtp_skb_cache_ctrl) * RTP_DSP_CHAN_MAX), GFP_KERNEL);
    if (!g_jitter_buffer_ctrl)
    {
        hook_info("kmalloc rtp_skb_cache_ctrl fail. \n");
        kfree(g_rtp_skb_cache_buffer);
        g_rtp_skb_cache_buffer = NULL;
        return -1;
    }

    err = 0;
    memset(g_jitter_buffer_ctrl, 0, (sizeof(struct rtp_skb_cache_ctrl) * RTP_DSP_CHAN_MAX));
    for (i = 0; i < RTP_DSP_CHAN_MAX; i++)
    {
        INIT_LIST_HEAD(&g_jitter_buffer_ctrl[i].cache_head);
        INIT_LIST_HEAD(&g_jitter_buffer_ctrl[i].list_free);
        spin_lock_init(&g_jitter_buffer_ctrl[i].lock);

        spin_lock_bh(&g_jitter_buffer_ctrl[i].lock);
        for (j = 0; j < RTP_JITTER_BUFFER_PKTS; j++)
        {
            list_add(&g_rtp_skb_cache_buffer[i*RTP_JITTER_BUFFER_PKTS + j].list, &g_jitter_buffer_ctrl[i].list_free);
            g_rtp_skb_cache_buffer[i*RTP_JITTER_BUFFER_PKTS + j].skb = NULL;
        }
        spin_unlock_bh(&g_jitter_buffer_ctrl[i].lock);
    }

    #ifdef RTP_JITTER_KTHREAD
    g_jitter_buffer_task = kthread_create(rtp_relay_jitter_buffer_kthread_func, NULL, "rtp_jitter_buffer");
    if (IS_ERR(g_jitter_buffer_task))
    {
        hook_info("create dsp jitter buffer kthread fial. \n");
        err = PTR_ERR(g_jitter_buffer_task);
        g_jitter_buffer_task = NULL;

        kfree(g_rtp_skb_cache_buffer);
        g_rtp_skb_cache_buffer = NULL;
        kfree(g_jitter_buffer_ctrl);
        g_jitter_buffer_ctrl = NULL;
        
        return err;
    }

    wake_up_process(g_jitter_buffer_task);
    #endif

    #ifdef RTP_JITTER_WORK_QUEUE
    g_jitter_buffer_wqueue = create_workqueue("xrtp_wqueue");
    if (!g_jitter_buffer_wqueue)
    {
        kfree(g_rtp_skb_cache_buffer);
        g_rtp_skb_cache_buffer = NULL;
        kfree(g_jitter_buffer_ctrl);
        g_jitter_buffer_ctrl = NULL;

        #ifdef RTP_JITTER_KTHREAD
        kthread_stop(g_jitter_buffer_task);
        g_jitter_buffer_task = NULL;
        #endif
        
        return -1;
    }
    INIT_WORK(&g_jitter_buffer_work, (work_func_t)rtp_relay_jitter_buffer_tx);
    queue_work(g_jitter_buffer_wqueue, &g_jitter_buffer_work);
    #endif

    #ifdef RTP_JITTER_BUFFER_HRTIMER
    rtp_relay_jitter_buffer_hrtimer_init();
    #endif

    return 0;
}

/* rtp�ں�ת��jitter buffer����ע�� */
static void rtp_relay_jitter_buffer_fini(void)
{
    struct rtp_skb_cache *entry, *n;
    int i;

    #ifdef RTP_JITTER_KTHREAD
    if (g_jitter_buffer_task)
    {
        kthread_stop(g_jitter_buffer_task);
        g_jitter_buffer_task = NULL;
    }
    #endif

    #ifdef RTP_JITTER_BUFFER_HRTIMER
    rtp_relay_jitter_buffer_hrtimer_fini();
    #endif

    #ifdef RTP_JITTER_WORK_QUEUE
    if (g_jitter_buffer_wqueue)
    {
        destroy_workqueue(g_jitter_buffer_wqueue);
        g_jitter_buffer_wqueue = NULL;
    }
    #endif

    if (g_jitter_buffer_ctrl)
    {
        for (i = 0; i < RTP_DSP_CHAN_MAX; i++)
        {
            spin_lock_bh(&g_jitter_buffer_ctrl[i].lock);
            list_for_each_entry_safe(entry, n, &g_jitter_buffer_ctrl[i].cache_head, list)
            {
                list_del(&entry->list);
                list_add(&entry->list, &g_jitter_buffer_ctrl[i].list_free);
                if (entry->skb)
                {
                    ip_local_out(entry->skb);
                    entry->skb = NULL;
                }
            }
            spin_unlock_bh(&g_jitter_buffer_ctrl[i].lock);
        }
        kfree(g_jitter_buffer_ctrl);
        g_jitter_buffer_ctrl = NULL;
    }

    if (g_rtp_skb_cache_buffer)
    {
        kfree(g_rtp_skb_cache_buffer);
        g_rtp_skb_cache_buffer = NULL;
    }
    
    return;
}
/* end   for rtp relay jitter buffer */

/* dump�ں�̬�·���������Ϣ */
static void rtp_print_cache_conn(struct rtp_relay_cache *cache)
{

    hook_info("kernel %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]<-->%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]\n",
                NIPQUAD(cache->aconn.local_ip.ip), htons(cache->aconn.local_port), NMACQUAD(cache->aconn.local_mac),
                NIPQUAD(cache->aconn.remote_ip.ip), htons(cache->aconn.remote_port), NMACQUAD(cache->aconn.remote_mac));
    hook_info("kernel %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]<-->%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]\n\n",
                NIPQUAD(cache->bconn.local_ip.ip), htons(cache->bconn.local_port), NMACQUAD(cache->bconn.local_mac),
                NIPQUAD(cache->bconn.remote_ip.ip), htons(cache->bconn.remote_port), NMACQUAD(cache->bconn.remote_mac));
  
    return;
}

/* dump�û�̬�·���������Ϣ */
static void rtp_print_user_media(struct rm_media_tbl *cache)
{

    hook_info("netlink(IPv%d) A %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]<-->%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]\n", 
                cache->aconn.ip_type,
                NIPQUAD(cache->aconn.local_ip.ip), cache->aconn.local_port, NMACQUAD(cache->aconn.local_mac),
                NIPQUAD(cache->aconn.remote_ip.ip), cache->aconn.remote_port, NMACQUAD(cache->aconn.remote_mac));
    hook_info("%d %s, param:%s, payload:%d, slience:%d, detect:%d, action:%d, bitrate:%d, size:%d rfc2833:%d, mlock:%d, %d\n", 
                cache->aconn.media_type, 
                cache->aconn.media_data.rtp.encode_name, cache->aconn.media_data.rtp.param, 
                cache->aconn.media_data.rtp.payload, cache->aconn.media_data.rtp.slience_supp,
                cache->aconn.media_data.rtp.dtmf_detect, cache->aconn.media_data.rtp.dtmf_action,
                cache->aconn.media_data.rtp.bitrate, cache->aconn.media_data.rtp.max_psize,
                cache->aconn.media_data.rtp.rfc2833, cache->aconn.remotelock, cache->aconn.media_data.rtp.max_ptime);
    
    hook_info("netlink(IPv%d) B %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]<-->%d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x]\n", 
                cache->bconn.ip_type,
                NIPQUAD(cache->bconn.local_ip.ip), cache->bconn.local_port, NMACQUAD(cache->bconn.local_mac),
                NIPQUAD(cache->bconn.remote_ip.ip), cache->bconn.remote_port, NMACQUAD(cache->bconn.remote_mac));
    hook_info("%d %s, param:%s, payload:%d, slience:%d, detect:%d, action:%d, bitrate:%d, size:%d rfc2833:%d, mlock:%d, %d\n", 
                cache->bconn.media_type,
                cache->bconn.media_data.rtp.encode_name, cache->bconn.media_data.rtp.param, 
                cache->bconn.media_data.rtp.payload, cache->bconn.media_data.rtp.slience_supp,
                cache->bconn.media_data.rtp.dtmf_detect, cache->bconn.media_data.rtp.dtmf_action,
                cache->bconn.media_data.rtp.bitrate, cache->bconn.media_data.rtp.max_psize,
                cache->bconn.media_data.rtp.rfc2833, cache->bconn.remotelock, cache->bconn.media_data.rtp.max_ptime);
   
    return;
}

static void rtp_dump_packet(struct sk_buff *skb)
{
    struct iphdr    *iph;
    struct udphdr   *udph;
    struct tcphdr   *tcph;
    struct ethhdr   *ethh;
    struct vlan_hdr *vlanh;

    ethh = eth_hdr(skb);
    if (ethh)
    {
        if (ethh->h_proto == htons(ETH_P_8021Q))
        {
            vlanh = (struct vlan_hdr *)(ethh + 1);
            hook_info("mac [%02x:%02x:%02x:%02x:%02x:%02x] --> [%02x:%02x:%02x:%02x:%02x:%02x] vlan id:%d/0x%X \n", 
                NMACQUAD(ethh->h_source), NMACQUAD(ethh->h_dest), 
                htons(vlanh->h_vlan_TCI), htons(vlanh->h_vlan_TCI));
        }
        else
        {
            hook_info("mac [%02x:%02x:%02x:%02x:%02x:%02x] --> [%02x:%02x:%02x:%02x:%02x:%02x] \n", 
                NMACQUAD(ethh->h_source), NMACQUAD(ethh->h_dest));
        }
    }

    iph = ip_hdr(skb);
    if (iph)
    {
        if (iph->protocol == IPPROTO_UDP)
        {
            udph = udp_hdr(skb);
            if (udph)
            {
                hook_info("UDP packet %d.%d.%d.%d:%u --> %d.%d.%d.%d:%u protocol:%u\n", 
                            NIPQUAD(iph->saddr), htons(udph->source), 
                            NIPQUAD(iph->daddr), htons(udph->dest), iph->protocol);
            }
        }
        else if (iph->protocol == IPPROTO_TCP)
        {
            tcph = tcp_hdr(skb);
            if (tcph)
            {
                hook_info("TCP packet %d.%d.%d.%d:%u --> %d.%d.%d.%d:%u protocol:%u\n", 
                            NIPQUAD(iph->saddr), htons(tcph->source), 
                            NIPQUAD(iph->daddr), htons(tcph->dest), iph->protocol);
            }
        }
    }

    return;
}

extern void capture_match_and_send(const struct sk_buff *skb,unsigned short port,int isrtp,int output);
#ifdef RTP_DRIVER_PKT_DISPATCH
extern int dinstar_dispatch_register(__u16 dstport, __u8 cpu);
extern int dinstar_dispatch_unregister(__u16 dstport);
extern int dinstar_dispatch_setbase(__u16 dstport);

/* rtp����cpu�ַ�ע�ᣬ�������������� */
static void rtp_packet_dispatch_config(__u16 cpu_base, __u16 cpu_nums)
{
    unsigned int i;
    unsigned int cpu_id = 0;
    
    if (cpu_nums == 0)
    {
        hook_info("error: cpu_base:%u, cpu_numbs:%u \n", cpu_base, cpu_nums);
        return;
    }

    dinstar_dispatch_setbase(0);
    
    for (i = 0; i < 65535; i += 2)
    {
        dinstar_dispatch_register(i,   (cpu_id%cpu_nums) + cpu_base);
        dinstar_dispatch_register(i+1, (cpu_id%cpu_nums) + cpu_base);
        cpu_id++;
    }

    return;
}

static void rtp_packet_dispatch_register(void)
{
    unsigned int i;
    unsigned int cpu_id = 0;
    
    if (core_cpu_nums == 0)
    {
        return;
    }

    dinstar_dispatch_setbase(0);
    
    for (i = 0; i < 65535; i += 2)
    {
        dinstar_dispatch_register(i,   (cpu_id%core_cpu_nums) + core_cpu_base);
        dinstar_dispatch_register(i+1, (cpu_id%core_cpu_nums) + core_cpu_base);
        cpu_id++;
    }

    return;
}

static void rtp_packet_dispatch_unregister(void)
{
    unsigned int i;

    if (core_cpu_nums == 0)
    {
        return;
    }
    
    for (i = 0; i < 65535; i++)
    {
        dinstar_dispatch_unregister(i);
    }

    return;
}

static void rtp_packet_dispatch_port(__u16 dport, __u8 cpu)
{
    if (core_cpu_nums == 0)
    {
        return;
    }
    
    dinstar_dispatch_register(dport, cpu);
    dinstar_dispatch_register(dport + 1, cpu);

    return;
}

static void rtp_packet_dispatch_unport(__u16 dport)
{
    if (core_cpu_nums == 0)
    {
        return;
    }

    dinstar_dispatch_unregister(dport);
    dinstar_dispatch_unregister(dport + 1);

    return;
}

#ifdef RTP_DYNAMIC_DISPATCH_CPU
#define RTP_CPUS_MAX    8

struct rtp_dynic_cpu {
    int power;
    int weight;
    int conns;
    unsigned char port_map[65536];
};

struct rtp_dynic_ctrl {
    int total_power;
    struct rtp_dynic_cpu cpus[RTP_CPUS_MAX];
};

static struct rtp_dynic_ctrl *g_rtp_dynic_ctrl = NULL;
static int core_cpu_power[8] = {150, 300, 200, 0, 0, 0, 0, 0};
static int g_rtp_cpu_nums;
module_param_array(core_cpu_power, int, &g_rtp_cpu_nums, 0444);

static void rtp_dynic_put_cpu(__u16 dport, __u8 cpu)
{
    g_rtp_dynic_ctrl->total_power++;
    g_rtp_dynic_ctrl->cpus[cpu].power++;
    g_rtp_dynic_ctrl->cpus[cpu].conns--;
    g_rtp_dynic_ctrl->cpus[cpu].port_map[dport] = 0;

    rtp_packet_dispatch_unport(dport);

    return;
}

/* ���һ��cpu��Ϊ����cpu */
static int rtp_dynic_hold_cpu(__u16 dport)
{
    int cpu, i;
    int power_max;

    if (!g_rtp_dynic_ctrl)
    {
        return core_cpu_base;
    }
    
    if (g_rtp_dynic_ctrl->total_power <= 0)
    {
        for (i = 0; i < g_rtp_cpu_nums; i++)
        {
            g_rtp_dynic_ctrl->cpus[i].power = core_cpu_power[i];
            g_rtp_dynic_ctrl->total_power += core_cpu_power[i];
        }
    }

    power_max = g_rtp_dynic_ctrl->cpus[core_cpu_base].power;
    cpu = core_cpu_base;
    for (i = (core_cpu_base + 1); i < (core_cpu_base + core_cpu_nums); i++)
    {
        if (power_max < g_rtp_dynic_ctrl->cpus[i].power)
        {
            power_max = g_rtp_dynic_ctrl->cpus[i].power;
            cpu = i;
        }
    }

    if (power_max <= 0)
    {
        /* ��ǰ��cpu��������£�ѡ����cpu */
        cpu = core_cpu_base + core_cpu_nums - 1;
    }

cpu_dispatch:    
    g_rtp_dynic_ctrl->total_power--;
    g_rtp_dynic_ctrl->cpus[cpu].power--;
    g_rtp_dynic_ctrl->cpus[cpu].conns++;
    g_rtp_dynic_ctrl->cpus[cpu].port_map[dport] = 1;

    rtp_packet_dispatch_port(dport, cpu);
    
    return cpu;
}

static void rtp_dynic_removal_cpu(void)
{
    int port, cpuid;
    int cpu = g_rtp_cpu_nums - 1;

    if (!g_rtp_dynic_ctrl)
    {
        return;
    }
   
    if (g_rtp_dynic_ctrl->cpus[cpu].power > 0)
    {
        g_rtp_dynic_ctrl->total_power -= g_rtp_dynic_ctrl->cpus[cpu].power;
        g_rtp_dynic_ctrl->cpus[cpu].power = 0;
    }

    for (port = g_rtp_port_min; port < g_rtp_port_max; port += 2)
    {
        if (g_rtp_dynic_ctrl->cpus[cpu].port_map[port])
        {
            cpuid = rtp_dynic_hold_cpu(port);
            rtp_packet_dispatch_port(port, cpuid);
            g_rtp_dynic_ctrl->cpus[cpu].port_map[port] = 1;
        }
    }

    return;
}

static void rtp_dynic_cpus_init(void)
{
    int i;

    if ((g_rtp_cpu_nums <= 0) || (core_cpu_nums <= 1))
    {
        return;
    }

    g_rtp_dynic_ctrl = (struct rtp_dynic_ctrl *)kmalloc(sizeof(struct rtp_dynic_ctrl), GFP_KERNEL);
    if (g_rtp_dynic_ctrl)
    {
        memset(g_rtp_dynic_ctrl, 0, sizeof(struct rtp_dynic_ctrl));
        for (i = 0; i < g_rtp_cpu_nums; i++)
        {
            g_rtp_dynic_ctrl->cpus[i].power = core_cpu_power[i];
            g_rtp_dynic_ctrl->total_power += core_cpu_power[i];
        }
    }
    
    return;
}

static void rtp_dynic_cpus_fini(void)
{
    if (g_rtp_dynic_ctrl)
    {
        kfree(g_rtp_dynic_ctrl);
        g_rtp_dynic_ctrl = NULL;
    }

    return;
}

#endif
#endif

/* if rfc2833 match, return true */
static int rtp_relay_is_rfc2833_match(struct udphdr *udph, struct rtphdr *rtph)
{
    if (htons(udph->len) != (sizeof(struct udphdr) + sizeof(struct rtphdr) + sizeof(struct rfc2833hdr)))
    {
        return 0;
    }
    else
        return 1;

}

/* ���û��㷢��rfc2833������Ϣ */
static void rtp_netlink_send_rfc2833_report(struct rtphdr *rtph,struct iphdr *iph,struct udphdr *udph)
{
    struct sk_buff *skb = NULL;
    struct nlmsghdr *nlh = NULL;
    struct rfc2833_report *report = NULL;
    struct rfc2833hdr *rfc2833h = NULL;
    int datalen;
    if(!g_rtp_user_pid)
    {
        LOG_INFO("g_rtp_user_pid 0, send rfc2833 report fail \r\n");
        return ;
    }
    rfc2833h = (struct rfc2833hdr *)(rtph + 1);
    datalen = NLMSG_SPACE(sizeof(struct rfc2833_report));

    skb = alloc_skb(datalen, GFP_ATOMIC);
    if(!skb)
    {
        LOG_INFO("alloc skb error.\r\n");
        return;
    }

    /* init send data */
    nlh = nlmsg_put(skb, 0, 0, 0, sizeof(struct rfc2833_report), 0);
    nlh->nlmsg_pid = 0;
    /* */
    nlh->nlmsg_type = RTP_MEDIA_TBL_RFC2833_REPORT;
    
    report = (struct rfc2833_report *)NLMSG_DATA(nlh);
    report->rfc2833.event_id = rfc2833h->event_id;
    report->rfc2833.flag =  rfc2833h->flag;
    report->rfc2833.event_duration = rfc2833h->event_duration;
    report->sport = udph->source;
    report->dport = udph->dest;
    report->u_saddr.in.s_addr = iph->saddr;
    report->u_daddr.in.s_addr = iph->daddr;
    
    netlink_unicast(rtp_nfnl, skb, g_rtp_user_pid, MSG_DONTWAIT);
    log_debug("netlink send rfc2833 report success, pid:%u \r\n",g_rtp_user_pid);
    return;    
}


/* ���û��㷢��������Ϣ���� */
static void rtp_netlink_send_ddos_report(struct rtp_media *conn)
{
    struct sk_buff *send_skb;
    struct nlmsghdr *nlh;
    struct ddos_report *report;
    int datalen;

    if (!g_rtp_user_notify_pid)
    {
        return;
    }

    datalen = NLMSG_SPACE(sizeof(struct ddos_report));

///-
    //send_skb = alloc_skb(datalen, GFP_KERNEL);
    send_skb = alloc_skb(datalen, GFP_ATOMIC);
    if(!send_skb)
    {
        hook_info("alloc skb error.\r\n");
        return;
    }

    /* init send data */
    nlh = nlmsg_put(send_skb, 0, 0, 0, sizeof(struct ddos_report), 0);
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_type = RTP_MEDIA_TBL_NOTIFY;
    
    report = (struct ddos_report *)NLMSG_DATA(nlh);
    report->msg_type = RTP_MEDIA_TBL_NOTIFY;

    report->ip_type = conn->ip_type;
    memcpy(&report->u_ipaddr, &conn->remote_ip, sizeof(struct in6_addr));
    //report->u_ipaddr = conn->remote_ip;
    report->port = htons(conn->remote_port);
    report->recv_pkts = conn->statis.recvpkts;
    report->recv_bytes = conn->statis.recvbytes;
    report->recv_rate = conn->statis.recvrate_rtime;
    
    if (g_debug_enable)
        hook_info("send ddps report host %d.%d.%d.%d to userspace process.\r\n", NIPQUAD(report->u_ipaddr.in.s_addr));
    
    netlink_unicast(rtp_nfnl, send_skb, g_rtp_user_notify_pid, MSG_DONTWAIT);

    return;
}

static int rtp_mac_is_zero(unsigned char *mac)
{
    if ((*(mac+0) == 0) && 
        (*(mac+1) == 0) && 
        (*(mac+2) == 0) && 
        (*(mac+3) == 0) && 
        (*(mac+4) == 0) && 
        (*(mac+5) == 0))
    {
        return 1;
    }

    return 0;
}

/* ת�����ӱ���Ĵ��� */
static int rtp_netlink_tbl_create(struct rm_media_tbl *tbl, int update_flag)
{
    struct rtp_ctrl_tbl *ctrl_tbl;
    struct rtp_relay_cache *cache, *rcache;
    __u16 connid;
    struct rtp_statis astat, bstat;
    
    if (g_debug_enable)
    {
        hook_info("create connID:%d. \r\n", tbl->conn_id);
        rtp_print_user_media(tbl);
    }

    /* check port invalid */
    if ((tbl->conn_id < g_rtp_port_min) || (tbl->conn_id >= g_rtp_port_max) || (tbl->conn_id & 0x1))
    {
        /* syslog: connid invalid. */
        hook_info("error: create media connection fail. invalid connID:%d.\r\n", tbl->conn_id);
        return -1;
    }

    /* rtp ���ļ��dspͨ���Ϸ���, bfcp          ���ü�� */
    if((tbl->aconn.media_type != RM_MEDIA_APPLICATION) && (tbl->aconn.protocol & IPPROTO_UDP))
    {
    if ((tbl->aconn.chan_id >= RTP_DSP_CHAN_MAX) || (tbl->bconn.chan_id >= RTP_DSP_CHAN_MAX))
    {
        /* syslog: chan_id invalid. */
        hook_info("error: invalid chanID:%d/%d.\r\n", tbl->aconn.chan_id, tbl->bconn.chan_id);
        return -1;
    }
    }

///-
    //cache = (struct rtp_relay_cache *)kmem_cache_alloc(g_rtp_cachep, GFP_KERNEL);
    cache = (struct rtp_relay_cache *)kmem_cache_alloc(g_rtp_cachep, GFP_ATOMIC);
    if (!cache)
    {
        hook_info("error: kmem cache fail. connID:%d.\r\n", tbl->conn_id);
        return -1;
    }
    memset(cache, 0, sizeof(struct rtp_relay_cache));
    cache->create_time = jiffies;

 
    /* ���aconn ip/port/mac��ַ��Ϣ */
    if ((tbl->aconn.ip_type & IP_TYPE_BIT_MASK) == 4)
    {
        cache->aconn.ip_type = PF_INET;
        cache->aconn.local_ip.ip = tbl->aconn.local_ip.ip;
        cache->aconn.remote_ip.ip = tbl->aconn.remote_ip.ip;

        /* ��¼ԭʼ�·���ip��ַ */
        cache->aconn.orig_remote_ip.ip = tbl->aconn.remote_ip.ip;
        if (g_debug_enable)
        {
            hook_info("aconn: local_ip:%d.%d.%d.%d, remote_ip:%d.%d.%d.%d, orig_remote_ip:%d.%d.%d.%d protocol %u\n",
                NIPQUAD(tbl->aconn.local_ip.ip), NIPQUAD(tbl->aconn.remote_ip.ip),
                NIPQUAD(tbl->aconn.remote_ip.ip),tbl->aconn.protocol);
        }
    }
    else if ((tbl->aconn.ip_type & IP_TYPE_BIT_MASK) == 6)
    {
        cache->aconn.ip_type = PF_INET6;
        memcpy(cache->aconn.local_ip.ip6, tbl->aconn.local_ip.ip6, sizeof(cache->aconn.local_ip.ip6));
        memcpy(cache->aconn.remote_ip.ip6, tbl->aconn.remote_ip.ip6, sizeof(cache->aconn.remote_ip.ip6));

        memcpy(cache->aconn.orig_remote_ip.ip6, tbl->aconn.remote_ip.ip6, sizeof(cache->aconn.orig_remote_ip.ip6));
    }
    else 
    {
        hook_info("error: Aconn IP Type(%d) invalid. connID:%d.\r\n", (tbl->aconn.ip_type & IP_TYPE_BIT_MASK), tbl->conn_id);
        kmem_cache_free(g_rtp_cachep, cache);
        return -1;
    }
    cache->aconn.local_port = htons(tbl->aconn.local_port);
    memcpy(cache->aconn.local_mac, tbl->aconn.local_mac, RM_ETH_ALEN);
    cache->aconn.remote_port = htons(tbl->aconn.remote_port);
    memcpy(cache->aconn.remote_mac, tbl->aconn.remote_mac, RM_ETH_ALEN);
    if(g_debug_enable)
    {
        hook_info("aconn local_port:%u local_mac:%02x:%02x:%02x:%02x:%02x:%02x "
            "remote_port:%u remote_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
            tbl->aconn.local_port, NMACQUAD(tbl->aconn.local_mac),
            tbl->aconn.remote_port, NMACQUAD(tbl->aconn.remote_mac));
    }

    cache->aconn.orig_remote_port = htons(tbl->aconn.remote_port);
    memcpy(cache->aconn.orig_remote_mac, tbl->aconn.remote_mac, RM_ETH_ALEN);
    if(g_debug_enable)
    {
        hook_info("aconn orig_remote_port:%u orig_remote_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
            tbl->aconn.remote_port, NMACQUAD(tbl->aconn.remote_mac));
    }

    /* ���bconn ip/port/mac��ַ��Ϣ */
    if ((tbl->bconn.ip_type & IP_TYPE_BIT_MASK) == 4)
    {
        cache->bconn.ip_type = PF_INET;
        cache->bconn.local_ip.ip = tbl->bconn.local_ip.ip;
        cache->bconn.remote_ip.ip = tbl->bconn.remote_ip.ip;

        cache->bconn.orig_remote_ip.ip = tbl->bconn.remote_ip.ip;
        if(g_debug_enable)
        {
            hook_info("bconn: local_ip:%d.%d.%d.%d, remote_ip:%d.%d.%d.%d, orig_remote_ip:%d.%d.%d.%d, protocol %u\n",
                NIPQUAD(tbl->bconn.local_ip.ip), NIPQUAD(tbl->bconn.remote_ip.ip),
                NIPQUAD(tbl->bconn.remote_ip.ip), tbl->bconn.protocol);
        }
    }
    else if ((tbl->bconn.ip_type & IP_TYPE_BIT_MASK) == 6)
    {
        cache->bconn.ip_type = PF_INET6;
        memcpy(cache->bconn.local_ip.ip6, tbl->bconn.local_ip.ip6, sizeof(cache->bconn.local_ip.ip6));
        memcpy(cache->bconn.remote_ip.ip6, tbl->bconn.remote_ip.ip6, sizeof(cache->bconn.remote_ip.ip6));

        memcpy(cache->bconn.orig_remote_ip.ip6, tbl->bconn.remote_ip.ip6, sizeof(cache->bconn.orig_remote_ip.ip6));
    }
    else
    {
        hook_info("error: Bconn IP Type(%d) invalid. connID:%d.\r\n", tbl->bconn.ip_type, tbl->conn_id);
        kmem_cache_free(g_rtp_cachep, cache);
        return -1;
    }
    //cache->bconn.local_ip.ip = tbl->bconn.local_ip.ip;
    cache->bconn.local_port = htons(tbl->bconn.local_port);
    memcpy(cache->bconn.local_mac, tbl->bconn.local_mac, RM_ETH_ALEN);
    
    //cache->bconn.remote_ip.ip = tbl->bconn.remote_ip.ip;
    cache->bconn.remote_port = htons(tbl->bconn.remote_port);
    memcpy(cache->bconn.remote_mac, tbl->bconn.remote_mac, RM_ETH_ALEN);

    if(g_debug_enable)
    {
        hook_info("bconn local_port:%u local_mac:%02x:%02x:%02x:%02x:%02x:%02x "
            "remote_port:%u remote_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
            tbl->bconn.local_port, NMACQUAD(tbl->bconn.local_mac),
            tbl->bconn.remote_port, NMACQUAD(tbl->bconn.remote_mac));
    }

    cache->bconn.orig_remote_port = htons(tbl->bconn.remote_port);
    memcpy(cache->bconn.orig_remote_mac, tbl->bconn.remote_mac, RM_ETH_ALEN);
    if(g_debug_enable)
    {
        hook_info("bconn orig_remote_port:%u orig_remote_mac:%02x:%02x:%02x:%02x:%02x:%02x\n",
            tbl->bconn.remote_port, NMACQUAD(tbl->bconn.remote_mac));
    }

    /* ���ת��������Ϣ */
    cache->aconn.dev = dev_get_by_name(&init_net, "eth0");
    cache->bconn.dev = cache->aconn.dev;

    cache->aconn.ref_conn = &cache->bconn;
    cache->bconn.ref_conn = &cache->aconn;

    /* ���ý��˨��Ϣ */
    cache->aconn.media_lock = tbl->aconn.remotelock;
    cache->aconn.media_lock_param = tbl->aconn.media_lock_param;
    if(g_debug_enable)
    {
        hook_info("aconn remotelock:%u media_lock_param:%u\n",
            tbl->aconn.remotelock, tbl->aconn.media_lock_param);
    }
    if (cache->aconn.media_lock_param == 0)
    {
        cache->aconn.media_lock_param = g_rtp_media_lock_pkts;
    }
    /* �����ϲ��·�mac��ַΪ0ʱ��ʹ��ý��ˢ�»��Ƹ���mac��ַ���� */
    if (rtp_mac_is_zero(cache->aconn.remote_mac))
    {
        if (cache->aconn.media_lock == 0)
        {
            cache->aconn.media_lock = 1;
        }
        cache->aconn.remote_ip.ip= 0;
        cache->aconn.remote_port = 0;
        hook_debug("rtp relay ConnID(%u) %d.%d.%d.%d:%u mac is 00:00:00:00:00:00! \n", tbl->conn_id, 
                    NIPQUAD(cache->aconn.remote_ip.ip), htons(cache->aconn.remote_port));
    }
    cache->bconn.media_lock = tbl->bconn.remotelock;
    cache->bconn.media_lock_param = tbl->bconn.media_lock_param;
    if(g_debug_enable)
    {
        hook_info("bconn remotelock:%u media_lock_param:%u\n",
            tbl->bconn.remotelock, tbl->bconn.media_lock_param);
    }
    if (cache->bconn.media_lock_param == 0)
    {
        cache->bconn.media_lock_param = g_rtp_media_lock_pkts;
    }
    /* �����ϲ��·�mac��ַΪ0ʱ��ʹ��ý��ˢ�»��Ƹ���mac��ַ���� */
    if (rtp_mac_is_zero(cache->bconn.remote_mac))
    {
        if (cache->bconn.media_lock == 0)
        {
            cache->bconn.media_lock = 1;
        }
        cache->bconn.remote_ip.ip = 0;
        cache->bconn.remote_port = 0;
        hook_debug("rtp relay ConnID(%u) %d.%d.%d.%d:%u mac is 00:00:00:00:00:00! \n", tbl->conn_id, 
                    NIPQUAD(cache->bconn.remote_ip.ip), htons(cache->bconn.remote_port));
    }
    if (g_debug_enable == 20)
    {
        cache->aconn.media_lock = 1;
        cache->bconn.media_lock = 1;
    }
    /* ����������ͺ�������ͬһ���߼��ӿڣ����⴦�� */
    if ((cache->aconn.local_ip.ip == cache->bconn.local_ip.ip) &&
        (cache->aconn.media_lock && cache->bconn.media_lock))
    {
        cache->aconn.remote_ip.ip = 0;
        cache->aconn.remote_port = 0;
        cache->aconn.media_lock = 1;        /* half lock */
        cache->aconn.media_sync_flag = 1;
        cache->bconn.remote_ip.ip = 0;
        cache->bconn.remote_port = 0;
        cache->bconn.media_lock = 1;
        cache->bconn.media_sync_flag = 1;

        if (g_debug_enable == 30)
        {
            /* do not reset orig, set only for test */
            cache->aconn.orig_remote_ip.ip = 0;
            cache->bconn.orig_remote_ip.ip = 0;
        }
    }
    /*�Ƿ��ڷ���rtp��ʱ��ֻ����ʹ��orig��ַ*/
    if(tbl->aconn.ip_type & USER_ONLY_USE_ORIG_FOR_SEND)
    {
        cache->aconn.flag |= KERNEL_ONLY_USE_ORIG_FOR_SEND;
    }
    if(tbl->bconn.ip_type & USER_ONLY_USE_ORIG_FOR_SEND)
    {
        cache->bconn.flag |= KERNEL_ONLY_USE_ORIG_FOR_SEND;
    }

    /* ���A��ý�����ͺ�Э������ */
    cache->aconn.media_type = tbl->aconn.media_type;
    cache->aconn.protocol = tbl->aconn.protocol;

    /* rtp������Ҫ����ת����Ϣ�ȣ�bfcp���� */
    if(tbl->aconn.media_type != RM_MEDIA_APPLICATION)
    {
    /* ���dspת����Ϣ */
    cache->aconn.dev_dsp = dev_get_by_name(&init_net, "lo");
    cache->bconn.dev_dsp = cache->aconn.dev_dsp;
    cache->aconn.chan_id = tbl->aconn.chan_id; 
    cache->bconn.chan_id = tbl->bconn.chan_id;
    if(g_debug_enable)
    {
        hook_info("aconn chan_id:%u bconn chan_id:%u\n",
            tbl->aconn.chan_id, tbl->bconn.chan_id);
    }
    /* ������Ϣ */
    if (g_debug_enable == 40)
    {
        cache->aconn.chan_id = 0; 
        cache->bconn.chan_id = 256;
    }

    /* ��ʼ��ͳ����Ϣ���Ա㶨ʱ����ʱ�����ʬ���� */
    cache->aconn.statis.recvrate = 600;
    cache->bconn.statis.recvrate = 600;

    /* ���rtp��Ϣ */
    memcpy(cache->aconn.media_data.rtp.encode_name, tbl->aconn.media_data.rtp.encode_name, RM_NAME_MAX_LEN);
    memcpy(cache->aconn.media_data.rtp.param, tbl->aconn.media_data.rtp.param, RM_NAME_MAX_LEN);
    cache->aconn.media_data.rtp.payload = tbl->aconn.media_data.rtp.payload;
    cache->aconn.media_data.rtp.slience_supp = tbl->aconn.media_data.rtp.slience_supp;
    cache->aconn.media_data.rtp.dtmf_detect = tbl->aconn.media_data.rtp.dtmf_detect;
    cache->aconn.media_data.rtp.dtmf_action = tbl->aconn.media_data.rtp.dtmf_action;
    cache->aconn.media_data.rtp.bitrate = tbl->aconn.media_data.rtp.bitrate;
    cache->aconn.media_data.rtp.max_psize = tbl->aconn.media_data.rtp.max_psize + sizeof(struct udphdr) + sizeof(struct rtphdr);
    cache->aconn.media_data.rtp.rfc2833 = tbl->aconn.media_data.rtp.rfc2833;
    cache->aconn.media_data.rtp.max_ptime = tbl->aconn.media_data.rtp.max_ptime;
    cache->aconn.media_data.rtp.rfc2833_remote = tbl->aconn.media_data.rtp.rfc2833_local;
    //cache->aconn.media_data.rtp.srtp = tbl->aconn.media_data.rtp.srtp;
    if(g_debug_enable)
    {
        hook_info("aconn media_type:%u encode_name:%s param:%s payload:%d slience_supp:%d "
            "dtmf_detect:%d dtmf_action:%d bitrate:%d max_psize:%d rfc2833:%d max_ptime:%d "
            "rfc2833_remote:%d\n", 
            tbl->aconn.media_type, tbl->aconn.media_data.rtp.encode_name, tbl->aconn.media_data.rtp.param,
            tbl->aconn.media_data.rtp.payload, tbl->aconn.media_data.rtp.slience_supp, 
            tbl->aconn.media_data.rtp.dtmf_detect, tbl->aconn.media_data.rtp.dtmf_action,
            tbl->aconn.media_data.rtp.bitrate, tbl->aconn.media_data.rtp.max_psize,
            tbl->aconn.media_data.rtp.rfc2833, tbl->aconn.media_data.rtp.max_ptime,
            tbl->aconn.media_data.rtp.rfc2833_local);
    }
    if (g_debug_enable == 45)
    {
        cache->aconn.media_data.rtp.srtp = 2;
    }
    }
    /* ���b conn ý�����ͺ�Э������ */
    cache->bconn.media_type = tbl->bconn.media_type;
    cache->bconn.protocol = tbl->bconn.protocol;
    
    /* bfcp �����������rtp��Ϣ */
    if(tbl->bconn.media_type != RM_MEDIA_APPLICATION)
    {
        /* rtp������Ҫ����ת����Ϣ�� */
    memcpy(cache->bconn.media_data.rtp.encode_name, tbl->bconn.media_data.rtp.encode_name, RM_NAME_MAX_LEN);
    memcpy(cache->bconn.media_data.rtp.param, tbl->bconn.media_data.rtp.param, RM_NAME_MAX_LEN);
    cache->bconn.media_data.rtp.payload = tbl->bconn.media_data.rtp.payload;
    cache->bconn.media_data.rtp.slience_supp = tbl->bconn.media_data.rtp.slience_supp;
    cache->bconn.media_data.rtp.dtmf_detect = tbl->bconn.media_data.rtp.dtmf_detect;
    cache->bconn.media_data.rtp.dtmf_action = tbl->bconn.media_data.rtp.dtmf_action;
    cache->bconn.media_data.rtp.bitrate = tbl->bconn.media_data.rtp.bitrate;
    cache->bconn.media_data.rtp.max_psize = tbl->bconn.media_data.rtp.max_psize + sizeof(struct udphdr) + sizeof(struct rtphdr);
    cache->bconn.media_data.rtp.rfc2833 = tbl->bconn.media_data.rtp.rfc2833;
    cache->bconn.media_data.rtp.max_ptime = tbl->bconn.media_data.rtp.max_ptime;
    cache->bconn.media_data.rtp.rfc2833_remote = tbl->bconn.media_data.rtp.rfc2833_local;
    //cache->bconn.media_data.rtp.srtp = tbl->bconn.media_data.rtp.srtp;
    if(g_debug_enable)
    {
        hook_info("bconn media_type:%u encode_name:%s param:%s payload:%d slience_supp:%d "
            "dtmf_detect:%d dtmf_action:%d bitrate:%d max_psize:%d rfc2833:%d max_ptime:%d "
            "rfc2833_remote:%d\n", 
            tbl->bconn.media_type, tbl->bconn.media_data.rtp.encode_name, tbl->bconn.media_data.rtp.param,
            tbl->bconn.media_data.rtp.payload, tbl->bconn.media_data.rtp.slience_supp, 
            tbl->bconn.media_data.rtp.dtmf_detect, tbl->bconn.media_data.rtp.dtmf_action,
            tbl->bconn.media_data.rtp.bitrate, tbl->bconn.media_data.rtp.max_psize,
            tbl->bconn.media_data.rtp.rfc2833, tbl->bconn.media_data.rtp.max_ptime,
            tbl->bconn.media_data.rtp.rfc2833_local);
    }
    if (g_debug_enable == 45)
    {
        cache->bconn.media_data.rtp.srtp = 2;
    }
    }

    /* ���dscp��Ϣ */
    cache->aconn.dscp = (__u8)tbl->aconn.dscp;
    cache->bconn.dscp = (__u8)tbl->bconn.dscp;
    if(g_debug_enable)
    {
        hook_info("aconn dscp:%d bconn dscp:%d\n", tbl->aconn.dscp, tbl->bconn.dscp);
    }
    if (g_debug_enable == 50)
    {
        cache->aconn.dscp = 15;
        cache->bconn.dscp = 16;
    }

    /* ���vlan��Ϣ */
    cache->aconn.vlanid = tbl->aconn.vlanid;
    cache->bconn.vlanid = tbl->bconn.vlanid;
    if(g_debug_enable)
    {
        hook_info("aconn vlanid:%d bconn vlanid:%d\n", tbl->aconn.vlanid, tbl->bconn.vlanid);
    }
    if (g_debug_enable == 60)
    {
        cache->aconn.vlanid = 20;
        //cache->bconn.vlanid = 21;
    }
    if (g_debug_enable == 61)
    {
        //cache->aconn.vlanid = 20;
        cache->bconn.vlanid = 21;
    }
    /* ���rtp��Ϣ�� app      ���Ͳ����Ϊû��rtp�ײ�            */
    if(tbl->aconn.media_type != RM_MEDIA_APPLICATION)
    {
    /* ���rtp qos��Ϣ������rtp���ʱ����ʼ��qos��Ϣ */
    if (cache->aconn.media_type == RM_MEDIA_AUDIO)
    {
        if (cache->aconn.media_data.rtp.max_ptime == 0)
        {
            hook_debug("aconn media max packet time is 0ms, set default 20ms \n");
            /* ����Ĭ��rtp���ʱ��Ϊ20ms */
            cache->aconn.media_data.rtp.max_ptime = 20;
        }
        
        //cache->aconn.qos_pkts.pkts_power = (1000/cache->aconn.media_data.rtp.max_ptime) * g_rtp_qos_pkts_power;
        cache->aconn.qos_pkts.pkts_power = g_rtp_qos_audio_pkts_count;
        cache->aconn.qos_pkts.pkts_rtime = cache->aconn.qos_pkts.pkts_power;
        cache->aconn.qos_pkts.last_update_time = jiffies;
    }
    else if(cache->aconn.media_type == RM_MEDIA_VIDEO)
    {
        cache->aconn.qos_pkts.pkts_power = g_rtp_qos_video_pkts_count;
        cache->aconn.qos_pkts.pkts_rtime = cache->aconn.qos_pkts.pkts_power;
        cache->aconn.qos_pkts.last_update_time = jiffies;
    }
    else if(cache->aconn.media_type == RM_MEDIA_IMAGE)
    {
        cache->aconn.qos_pkts.pkts_power = g_rtp_qos_image_pkts_count;
        cache->aconn.qos_pkts.pkts_rtime = cache->aconn.qos_pkts.pkts_power;
        cache->aconn.qos_pkts.last_update_time = jiffies;
    }
    else
    {
        hook_debug("aconn invalid media type %d\n", cache->aconn.media_type);
    }
    if (cache->bconn.media_type == RM_MEDIA_AUDIO)
    {
        if (cache->bconn.media_data.rtp.max_ptime == 0)
        {
            hook_debug("bconn media max packet time is 0ms, set default 20ms \n");
            /* ����Ĭ��rtp���ʱ��Ϊ20ms */
            cache->bconn.media_data.rtp.max_ptime = 20;
        }
        
        //cache->bconn.qos_pkts.pkts_power = (1000/cache->bconn.media_data.rtp.max_ptime) * g_rtp_qos_pkts_power;
        cache->bconn.qos_pkts.pkts_power = g_rtp_qos_audio_pkts_count;
        cache->bconn.qos_pkts.pkts_rtime = cache->bconn.qos_pkts.pkts_power;
        cache->bconn.qos_pkts.last_update_time = jiffies;
    }
    else if(cache->bconn.media_type == RM_MEDIA_VIDEO)
    {
        cache->bconn.qos_pkts.pkts_power = g_rtp_qos_video_pkts_count;
        cache->bconn.qos_pkts.pkts_rtime = cache->bconn.qos_pkts.pkts_power;
        cache->bconn.qos_pkts.last_update_time = jiffies;
    }
    else if(cache->bconn.media_type == RM_MEDIA_IMAGE)
    {
        cache->bconn.qos_pkts.pkts_power = g_rtp_qos_image_pkts_count;
        cache->bconn.qos_pkts.pkts_rtime = cache->bconn.qos_pkts.pkts_power;
        cache->bconn.qos_pkts.last_update_time = jiffies;
    }
    else
    {
        hook_debug("bconn invalid media type %d\n", cache->bconn.media_type);
    }

    /* �������ӷ���ʱ�����Ϣ */
    #ifdef RTP_PACKET_TIME_DELAY
    cache->aconn.last_rx = 0;
    cache->aconn.delay_min = g_rtp_hz_ticks;
    cache->aconn.delay_max = 0;
    cache->aconn.delay_pktin_min = g_rtp_hz_ticks;
    
    cache->bconn.last_rx = 0;
    cache->bconn.delay_min = g_rtp_hz_ticks;
    cache->bconn.delay_max = 0;
    cache->bconn.delay_pktin_min = g_rtp_hz_ticks;
    #endif
    
    
    if (g_debug_enable == 100)
    {
        rtp_print_cache_conn(cache);
    }
    }


    connid = (__u16)tbl->conn_id;

    /* ���ý������Ϊrtp���ĵ������Ϣ */
    if((tbl->aconn.media_type != RM_MEDIA_APPLICATION) && (tbl->aconn.protocol & IPPROTO_UDP))
    {
        /* 
        ��������rtcp��Ϣ��ֻ��rtp���ĲŻ���rtcp��Ϣ�����Խ��ý�����ͺ�Э�����ͼ����ж� */
        ctrl_tbl = &g_rtp_ctrl_tbl[0][connid + 1];
    rtp_write_lock(&ctrl_tbl->lock);
    if (ctrl_tbl->cache != NULL)
    {
        kmem_cache_free(g_rtp_cachep, ctrl_tbl->cache);
        ctrl_tbl->cache = NULL;
    }
    rtp_write_unlock(&ctrl_tbl->lock);

    /* ��ʼ������ת������ʱ��ͳ����Ϣ */
    memset(&astat, 0, sizeof(struct rtp_statis));
    memset(&bstat, 0, sizeof(struct rtp_statis));
    }
    
    if((tbl->aconn.protocol & IPPROTO_UDP) && (tbl->aconn.protocol == tbl->bconn.protocol))
    {
        ctrl_tbl = &g_rtp_ctrl_tbl[0][connid];
    }
    else if((tbl->aconn.protocol & IPPROTO_TCP) && (tbl->aconn.protocol == tbl->bconn.protocol))
    {
        ctrl_tbl = &g_rtp_ctrl_tbl[1][connid];
    }
    else
    {
        log_warn("unrecognized protocol %d, create relay table fail \r\n", tbl->aconn.protocol);
        kmem_cache_free(g_rtp_cachep, cache);
        return -1;
    }
    // ����ɵ�ת������
    rtp_write_lock(&ctrl_tbl->lock);
    if (ctrl_tbl->cache != NULL)
    {
        if(!update_flag)
            hook_info("warning: connID:%d is busy. operation will cover the cache.\r\n", tbl->conn_id);
        /* ��app ý�����ͣ���Ҫ�������ͳ����Ϣ */
        if((tbl->aconn.media_type != RM_MEDIA_APPLICATION) && (tbl->aconn.protocol & IPPROTO_UDP))
        {            
            /* rtp���ͣ�����ת��������Ϣ */
        if (update_flag)
        {
            astat = ctrl_tbl->cache->aconn.statis;
            bstat = ctrl_tbl->cache->bconn.statis;
            hook_debug("info: connID:%d update connection. operation cover the cache.\r\n", tbl->conn_id);
        }

        if (ctrl_tbl->cache->aconn.chan_id > 0)
        {
            g_rtp_dsp_conns_count--;
        }
            g_rtp_conns_count--;
            atomic_dec(&g_rtp_atomic_conns_count);
        }
        
        kmem_cache_free(g_rtp_cachep, ctrl_tbl->cache);
        /* person habit */
        ctrl_tbl->cache = NULL;
    }
    
    /* �����½���ת������ */
    ctrl_tbl->cache = cache;
    if((tbl->aconn.media_type != RM_MEDIA_APPLICATION) && (tbl->aconn.protocol & IPPROTO_UDP))
    {
    /* ����ת��������Ϣ */
    if (update_flag)
    {
        ctrl_tbl->cache->aconn.statis = astat;
        ctrl_tbl->cache->bconn.statis = bstat;
    }

    if (cache->aconn.chan_id >= 0)
    {
        g_rtp_dsp_chan_entry[cache->aconn.chan_id].dir = RTP_DSP_CHAN_DIR_ORIGINAL;
        g_rtp_dsp_chan_entry[cache->aconn.chan_id].connid = connid;
        g_rtp_dsp_conns_count++;
    }
    if (cache->bconn.chan_id >= 0)
    {
        g_rtp_dsp_chan_entry[cache->bconn.chan_id].dir = RTP_DSP_CHAN_DIR_REPLY;
        g_rtp_dsp_chan_entry[cache->bconn.chan_id].connid = connid;
    }
    g_rtp_conns_count++;

    }
    rtp_write_unlock(&ctrl_tbl->lock);

    /* RTPý��������Ҫ����rtcp��Ϣ */
    if((tbl->aconn.media_type != RM_MEDIA_APPLICATION) && (tbl->aconn.protocol & IPPROTO_UDP))
    {
    /* ���rtcp������Ϣ */
        ctrl_tbl = &g_rtp_ctrl_tbl[0][connid + 1];
    rtp_write_lock(&ctrl_tbl->lock);
    rcache = (struct rtp_relay_cache *)kmem_cache_alloc(g_rtp_cachep, GFP_ATOMIC);
    if (rcache != NULL)
    {
        memcpy(rcache, cache, sizeof(struct rtp_relay_cache));
        rcache->aconn.local_port = htons(tbl->aconn.local_port + 1);
        rcache->aconn.remote_port = htons(tbl->aconn.remote_port + 1);
        rcache->aconn.orig_remote_port = htons(tbl->aconn.remote_port + 1);
        rcache->aconn.ref_conn = &rcache->bconn;

        rcache->bconn.local_port = htons(tbl->bconn.local_port + 1);
        rcache->bconn.remote_port = htons(tbl->bconn.remote_port + 1);
        rcache->bconn.orig_remote_port = htons(tbl->bconn.remote_port + 1);
        rcache->bconn.ref_conn = &rcache->aconn;
    }
    ctrl_tbl->cache = rcache;
        hook_debug("create rtcp connid %d \r\n", connid+1);
    rtp_write_unlock(&ctrl_tbl->lock);

    atomic_inc(&g_rtp_atomic_conns_count);
    }

    return 0;
}

/* ת�����ӱ����ɾ�� */
static void rtp_netlink_tbl_delete(unsigned int connid, unsigned int protocol)
{
    struct rtp_ctrl_tbl *ctrl_tbl = NULL;
    unsigned int proto = protocol;
    
    /* check port invalid */
    if ((connid < g_rtp_port_min) || (connid >= g_rtp_port_max) || (connid & 0x1))
    {
        /* syslog: connid invalid. */
        hook_info("error: delete media connection fail. invalid connID:%d.\r\n", connid);
        return;
    }
    hook_debug("rtp_netlink delete connid:%d, protocol:%u", connid, protocol);
    if(proto & (unsigned int)IPPROTO_UDP)
    {
        ctrl_tbl = &g_rtp_ctrl_tbl[0][connid + 1];
    rtp_write_lock(&ctrl_tbl->lock);
    if (ctrl_tbl->cache != NULL)
    {
        kmem_cache_free(g_rtp_cachep, ctrl_tbl->cache);
        ctrl_tbl->cache = NULL;
    }
    rtp_write_unlock(&ctrl_tbl->lock);

        ctrl_tbl = &g_rtp_ctrl_tbl[0][connid];
    }
    else if(proto & (unsigned int)IPPROTO_TCP)
    {
        ctrl_tbl = &g_rtp_ctrl_tbl[1][connid];
    }
    else
    {   
        log_warn("can't delete media conn,unrecognized protocol %d \r\n", proto);
        return ;
    }
    if(ctrl_tbl == NULL)
    {
        log_warn("media conn null, delete media fail \r\n");
        return ;
    }
    rtp_write_lock(&ctrl_tbl->lock);
    if (ctrl_tbl->cache != NULL)
    {
        /* RTPý������ */
        if((ctrl_tbl->cache->aconn.media_type != RM_MEDIA_APPLICATION) && (ctrl_tbl->cache->aconn.protocol & IPPROTO_UDP))
        {
        if (ctrl_tbl->cache->aconn.chan_id >= 0)
        {
            g_rtp_dsp_chan_entry[ctrl_tbl->cache->aconn.chan_id].dir = 0;
            g_rtp_dsp_chan_entry[ctrl_tbl->cache->aconn.chan_id].connid = 0;
        }
        if (ctrl_tbl->cache->bconn.chan_id >= 0)
        {
            g_rtp_dsp_chan_entry[ctrl_tbl->cache->bconn.chan_id].dir = 0;
            g_rtp_dsp_chan_entry[ctrl_tbl->cache->bconn.chan_id].connid = 0;
        }
        
        /* ����ɾ�����ϱ�ͳ����Ϣ���û�̬������̣�Ŀǰֻ�а�ȫ������̹�ע��֪ͨ */
        //rtp_netlink_send_report(connid, ctrl_tbl->cache);
        
        hook_debug("connID:%d live times:%lus, chanID(%d/%d) Aconn:%u/%u, Bconn:%u/%u \r\n", 
                    connid, (jiffies - ctrl_tbl->cache->create_time) / g_rtp_hz_ticks, 
                    ctrl_tbl->cache->aconn.chan_id, ctrl_tbl->cache->bconn.chan_id, 
                    ctrl_tbl->cache->aconn.statis.recvpkts, ctrl_tbl->cache->aconn.statis.recvbytes, 
                    ctrl_tbl->cache->bconn.statis.recvpkts, ctrl_tbl->cache->bconn.statis.recvbytes);
            g_rtp_conns_count--;
            atomic_dec(&g_rtp_atomic_conns_count);

        }
        
        kmem_cache_free(g_rtp_cachep, ctrl_tbl->cache);
        ctrl_tbl->cache = NULL;
    }
    else
    {
        /* ɾ�������ڵ����ӣ�����澯��Ϣ */
        hook_info("warning: delete media table:%d is not exist.\r\n", connid);
    }
    rtp_write_unlock(&ctrl_tbl->lock);

    return;
}

static void rtp_netlink_tbl_delete_all(void)
{
    unsigned int connid;

    for (connid = g_rtp_port_min; connid < g_rtp_port_max; connid += 2)
    {
        rtp_netlink_tbl_delete(connid, (unsigned int)IPPROTO_UDP);
        rtp_netlink_tbl_delete(connid, (unsigned int)IPPROTO_TCP);        
    }

    return;
}

static void rtp_capture_add(struct rtp_capture_media *rtp_capture)
{
    unsigned int port;
    if(NULL == rtp_capture)
    {
        hook_info("invalid args\n");
        return;
    }

    if ((rtp_capture->port < g_rtp_port_min) || (rtp_capture->port >= g_rtp_port_max) || (rtp_capture->port & 0x1))
    {
        hook_info("invalid port:%u\n", rtp_capture->port);
        return;
    }
    port = rtp_capture->port;

    if(NULL == g_rtp_ctrl_tbl[0])
    {
        hook_info("connid:%d ctl tbl has not create yet\n", port);
        return;
    }

    printk(KERN_INFO "port %d capture start\n", port);
    rtp_write_lock(&g_rtp_ctrl_tbl[0][port].lock);
    g_rtp_ctrl_tbl[0][port].captrue_flag = 1;
    g_rtp_ctrl_tbl[0][port+1].captrue_flag = 1;
    rtp_write_unlock(&g_rtp_ctrl_tbl[0][port].lock);

    return;
}

static void rtp_capture_del(struct rtp_capture_media *rtp_capture)
{
    unsigned int port;
    if(NULL == rtp_capture)
    {
        hook_info("invalid args\n");
        return;
    }

    if ((rtp_capture->port < g_rtp_port_min) || (rtp_capture->port >= g_rtp_port_max) || (rtp_capture->port & 0x1))
    {
        hook_info("invalid port:%u\n", rtp_capture->port);
        return;
    }
    port = rtp_capture->port;

    if(NULL == g_rtp_ctrl_tbl[0])
    {
        hook_info("connid:%d ctl tbl has not create yet\n", port);
        return;
    }
    printk(KERN_INFO "port %d capture stop\n", port);

    rtp_write_lock(&g_rtp_ctrl_tbl[0][port].lock);
    g_rtp_ctrl_tbl[0][port].captrue_flag = 0;
    g_rtp_ctrl_tbl[0][port+1].captrue_flag = 0;
    rtp_write_unlock(&g_rtp_ctrl_tbl[0][port].lock);

    return;
}

/* netlink��Ϣ�ַ������� */
static int rtp_netlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    //unsigned int *value;
    struct rm_delete_conn *value;
    struct rm_media_tbl *rm_media_tbl_info;
    struct rtp_port_range *config;
    struct rtp_dispatch_cpu *cpu_config;
    /** struct rtp_relay_cache *cache;
    int i; **/
    
    hook_debug("recv msg type:%d, pid:%d\r\n", nlh->nlmsg_type, nlh->nlmsg_pid);
    
    switch (nlh->nlmsg_type)
    {
        case RTP_MEDIA_TBL_CREATE:
            //hook_debug("kernel exec create.\r\n");
			rm_media_tbl_info = (struct rm_media_tbl *)NLMSG_DATA(nlh);
            (void)rtp_netlink_tbl_create(rm_media_tbl_info, 0);
            
            break;

        case RTP_MEDIA_TBL_UPDATE:
            //hook_debug("kernel exec create.\r\n");
			rm_media_tbl_info = (struct rm_media_tbl *)NLMSG_DATA(nlh);
            (void)rtp_netlink_tbl_create(rm_media_tbl_info, 1);
            
            break;

        case RTP_MEDIA_TBL_DELETE:
            //hook_debug("kernel exec delete.\r\n");
            value = (struct rm_delete_conn *)NLMSG_DATA(nlh);
            (void)rtp_netlink_tbl_delete(value->connid, value->protocol);
           //value = (unsigned int *)NLMSG_DATA(nlh);
           //(void)rtp_netlink_tbl_delete(*value, (unsigned int)IPPROTO_UDP);
            
            break;

        case RTP_MEDIA_TBL_SETCFG:
            g_rtp_user_pid = nlh->nlmsg_pid;

            #ifdef RTP_DRIVER_PKT_DISPATCH
            //rtp_packet_dispatch_unregister(g_rtp_port_min, g_rtp_port_max);
            #endif
            
            config = (struct rtp_port_range *)NLMSG_DATA(nlh);
            g_rtp_port_min = (__u16)config->port_min;
            g_rtp_port_max = (__u16)config->port_max;

            #ifdef RTP_DRIVER_PKT_DISPATCH
            //rtp_packet_dispatch_register(g_rtp_port_min, g_rtp_port_max, core_cpu_nums);
            #endif
                
            break;

        case RTP_MEDIA_TBL_DELALL:
            rtp_netlink_tbl_delete_all();
            
            break;

        case RTP_MEDIA_TBL_SETCPU:
            cpu_config = (struct rtp_dispatch_cpu *)NLMSG_DATA(nlh);
            #ifdef RTP_DRIVER_PKT_DISPATCH
            rtp_packet_dispatch_config((__u16)cpu_config->cpu_base, (__u16)cpu_config->cpu_nums);
            #endif
            
            break;

        case RTP_MEDIA_TBL_SET_SLOT_ID:
            g_master_solt_id = *((unsigned *)NLMSG_DATA(nlh));
            g_dtsl_redirect_mac[ETH_ALEN - 1] = (g_master_solt_id + 1);
            break;

        case RTP_MEDIA_TBL_NOTIFY:
            g_rtp_user_notify_pid = nlh->nlmsg_pid;
            break;

        case RTP_MEDIA_TBL_UNNOTIFY:
            g_rtp_user_notify_pid = 0;
            break;

        case RTP_MEDIA_TBL_CAPTURE_START:
            {
                struct rtp_capture_media *rtp_capture_p = NULL;
                rtp_capture_p = (struct rtp_capture_media *)NLMSG_DATA(nlh);
                rtp_capture_add(rtp_capture_p);
            }
            break;
            
        case RTP_MEDIA_TBL_CAPTURE_STOP:
            {
                struct rtp_capture_media *rtp_capture_p = NULL;
                rtp_capture_p = (struct rtp_capture_media *)NLMSG_DATA(nlh);
                rtp_capture_del(rtp_capture_p);
            }
            break;
            
        case RTP_MEDIA_TBL_DEBUG_ENABLE:
            g_rtp_log_enable = 1;
            break;
            
        case RTP_MEDIA_TBL_DEBUG_DISABLE:
            g_rtp_log_enable = 0;
            break;            
            
        default:
            hook_info("invalid netlink message type.\r\n");
            break;
    }

    return 0;
}

/* netlink�ձ�������� */
static void rtp_netlink_rcv(struct sk_buff *skb)
{
    int res;
	res = netlink_rcv_skb(skb, &rtp_netlink_rcv_msg);

    return;
}

/*  ͳ��rtp�������ݰ�*/
static void rtp_qos_rate_statis_v4(struct iphdr *iph, struct rtp_media *conn)
{
    if(conn->media_type != RM_MEDIA_APPLICATION)
    {
    conn->statis.recvpkts++;
    conn->statis.recvbytes += htons(iph->tot_len);
    conn->statis.recvrate += htons(iph->tot_len);
    }

    return;
}

static unsigned int g_rtp_match_rate = 0;
/* dump���ݰ���Ϣ */
static void rtp_packet_dump_limit(struct sk_buff *skb)
{
    struct iphdr    *iph;
    struct udphdr   *udph;
    struct ethhdr   *ethh;

    iph  = ip_hdr(skb);
    if(iph->protocol == IPPROTO_UDP)
    {
    udph = udp_hdr(skb);
    ethh = eth_hdr(skb);

    /* ÿ512�����һ����Ϣ */
    if ((g_rtp_match_rate & 0x1ff) == 0)
    {
        hook_info("hook packet src ip:%d.%d.%d.%d, port:%d, mac:[%02x:%02x:%02x:%02x:%02x:%02x].\r\n", 
                    NIPQUAD(iph->saddr), htons(udph->source), NMACQUAD(ethh->h_source));
        hook_info("            dst ip:%d.%d.%d.%d, port:%d, mac:[%02x:%02x:%02x:%02x:%02x:%02x].\r\n",
                    NIPQUAD(iph->daddr), htons(udph->dest), NMACQUAD(ethh->h_dest));
    }
    g_rtp_match_rate++;
    }

    return;
}

/* ���ݱ�����Ϣ����ý��˨��Ϣ */
static void rtp_media_lock_update_v4(int media_mode, 
            struct rtp_media *in_conn, 
            struct ethhdr *ethh, 
            struct iphdr  *iph, 
            struct udphdr *udph, 
            unsigned int connid,
            struct sk_buff *skb)
{
    struct rtphdr *rtph;
    struct tcphdr *tcph;    
    __be16 dport;
    __be16 sport;
    if(iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);
        dport = tcph->dest;
        sport = tcph->source;
    }
    else
    {
        dport = udph->dest;
        sport = udph->source;
    }
    
    switch (media_mode)
    {
        /* �ϸ����� */
        case 0:
            /* do nothing */
            break;
        
        /* ý��ת�����̬����:����ͨ��50��RTP��������ת������ */
        case 1:
            if ((iph->saddr != in_conn->remote_ip.ip) || (sport != in_conn->remote_port))
            {
                hook_debug("update media lock1 connid(%u): %d.%d.%d.%d:%u --> %d.%d.%d.%d:%u \n", 
                            htons(in_conn->local_port), 
                            NIPQUAD(in_conn->remote_ip.ip), htons(in_conn->remote_port), 
                            NIPQUAD(iph->saddr), htons(sport));
                
                in_conn->media_lock_status_ptks = 0;
                in_conn->remote_ip.ip = iph->saddr;
                in_conn->remote_port = sport;
                if (likely(ethh))
                {
                    memcpy(in_conn->remote_mac, ethh->h_source, ETH_ALEN);
                }

                if(RM_MEDIA_APPLICATION != in_conn->media_type)
                {
                if ((RM_MEDIA_IMAGE != in_conn->media_type) && (!(connid & 0x1)))
                {
                    /* rtp */
                    rtph = (struct rtphdr *)(udph + 1);
                    in_conn->media_lock_ssrc = rtph->rtp_ssrc;
                }
            }
            }
            
            in_conn->media_lock_status_ptks++;
            if (in_conn->media_lock_status_ptks >= g_rtp_media_lock_pkts)
            {
                /* ����30����������ת������ */
                in_conn->media_lock = 0;
            }
            
            break;

        /* ý��ת��������� */
        case 2:
            if (in_conn->remote_ip.ip != iph->saddr)
            {
                hook_debug("update media lock2 connid(%u): %d.%d.%d.%d:%u --> %d.%d.%d.%d:%u \n", 
                            htons(in_conn->local_port), 
                            NIPQUAD(in_conn->remote_ip.ip), htons(in_conn->remote_port), 
                            NIPQUAD(iph->saddr), htons(sport));
                
                in_conn->remote_ip.ip = iph->saddr;
                if (likely(ethh))
                {
                    memcpy(in_conn->remote_mac, ethh->h_source, ETH_ALEN);
                }
            }
            if (in_conn->remote_port != sport)
            {
                hook_debug("update media lock2 connid(%u): %d.%d.%d.%d:%u --> %d.%d.%d.%d:%u \n", 
                            htons(in_conn->local_port), 
                            NIPQUAD(in_conn->remote_ip.ip), htons(in_conn->remote_port), 
                            NIPQUAD(iph->saddr), htons(sport));
                in_conn->remote_port = sport;
            }

            break;

        /* ý��ת�������װ����� */
        case 3:
            if ((iph->saddr != in_conn->remote_ip.ip) || (sport != in_conn->remote_port))
            {
                hook_debug("update media lock3 connid(%u): %d.%d.%d.%d:%u --> %d.%d.%d.%d:%u \n", 
                            htons(in_conn->local_port), 
                            NIPQUAD(in_conn->remote_ip.ip), htons(in_conn->remote_port), 
                            NIPQUAD(iph->saddr), htons(sport));
                
                in_conn->media_lock_status_ptks = 1;
                in_conn->remote_ip.ip = iph->saddr;
                in_conn->remote_port = sport;
                if (likely(ethh))
                {
                    memcpy(in_conn->remote_mac, ethh->h_source, ETH_ALEN);
                }
            }
            in_conn->media_lock = 0;

            break;
        
        default:
            
            break;
    }

    return;
}

/* ý��˨�Ĵ��� */
static int rtp_media_lock_match_v4(struct ethhdr *ethh, struct iphdr *iph, struct udphdr *udph, struct rtp_media *conn)
{
    if (iph->daddr == conn->local_ip.ip)
    {
        /* ý��˨�����Ƶ�rtp���ĺϷ��Լ��� */
        #if 0
        if ((iph->saddr != conn->remote_ip.ip) || (udph->source != conn->remote_port))
        {
            conn->media_lock_status_ptks = 0;
            conn->remote_ip.ip = iph->saddr;
            conn->remote_port = udph->source;
            if (likely(ethh))
            {
                memcpy(conn->remote_mac, ethh->h_source, ETH_ALEN);
            }
        }
        
        conn->media_lock_status_ptks++;
        if (conn->media_lock_status_ptks >= g_rtp_media_lock_pkts)
        {
            /* ����30����������ת������ */
            conn->media_lock = 0;
        }
        #endif

        return 1;
    }

    return 0;
}

/* rtp����qos���������0��ʾ���������ںϷ���Χ�� */
static int rtp_relay_qos_check(struct sk_buff *skb, struct rtp_media *fwconn)
{
    struct rtp_qos_pkts *qos = &fwconn->qos_pkts;

    if(fwconn->media_type != RM_MEDIA_APPLICATION)
    {
    if ((jiffies - qos->last_update_time) >= g_rtp_hz_ticks)
    {
        qos->last_update_time = jiffies;
        qos->pkts_rtime = qos->pkts_power;
    }
    
    if (qos->pkts_rtime <= 0)
    {
        /* �Զ˷��Ͱ����ʳ���qos���� */
        return -1;
    }
    qos->pkts_rtime--;
    }

    return 0;
}

/* ֱ�Ӱ�ת������ */
static int __rtp_relay_encode_rtp2dsp_v4(struct sk_buff *skb, struct rtp_media *fwconn, __u16 connid)
{
    struct iphdr *iph = ip_hdr(skb);
	struct udphdr *udph = udp_hdr(skb);
    __u16 udp_len;

    /* �޸�ip����ͷ����ת�� */
    iph->saddr = in_aton("127.0.0.1");
    iph->daddr = iph->saddr;
    iph->check = 0;

    udph->source = fwconn->local_port;
    udph->dest = htons(8090);

    udph->check = 0; 
    udp_len = ntohs(udph->len);                               
    skb->csum = csum_partial(skb_transport_header(skb), udp_len, 0);
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len, IPPROTO_UDP, skb->csum);
    skb->ip_summed = CHECKSUM_NONE;
    if (0 == udph->check)
    {
	    udph->check = CSUM_MANGLED_0;
    }
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

    return 0;
}

/* ipv4������dspת�뱨�Ĵ��� */
static int rtp_relay_encode_rtp2dsp_v4(struct sk_buff *skb, struct rtp_media *fwconn, __u16 connid)
{
    struct iphdr  *ip=NULL, *newip = NULL;
	struct udphdr *udp=NULL, *newudp = NULL;
	ST_DSP_SOCK_DATA *dsphdr = NULL;
	int udphoff = 0;
    //struct ethhdr *ethh;
    struct rtphdr *rtph;
    
    ip = ip_hdr(skb);
    udphoff = ip_hdrlen(skb);
    skb_set_transport_header(skb, udphoff);
    udp = udp_hdr(skb);
    /* rtp�����غɵ�dtmf rfc2833ת�� */
    if (!(connid & 0x1))
    {
        rtph = (struct rtphdr *)(udp + 1);
        
        if ((fwconn->media_data.rtp.rfc2833) &&
            (rtph->rtp_paytype != fwconn->media_data.rtp.payload) &&
            (htons(udp->len) == (sizeof(struct udphdr) + sizeof(struct rtphdr) + sizeof(struct rfc2833hdr))))
        {
            hook_debug("timestamp:%lld, transform rfc2833(%d.%d.%d.%d->%d.%d.%d.%d) %u->%u \n", ktime_to_ms(skb->tstamp), 
                        NIPQUAD(ip->saddr), NIPQUAD(ip->daddr), 
                        rtph->rtp_paytype, fwconn->media_data.rtp.rfc2833);

            if (rtph->rtp_paytype != fwconn->media_data.rtp.rfc2833)
            {
                rtph->rtp_paytype = fwconn->media_data.rtp.rfc2833;
            }
        }
    }

    if (skb_headroom(skb) < sizeof(ST_DSP_SOCK_DATA))
    {
        hook_info("ERROR: no space to extend udp dsp head. \n");
        //û���㹻�ռ䣬����������
        return -1;
    }
        
    //��չͷ���ռ��dsp��Ϣ
    skb_push(skb, sizeof(ST_DSP_SOCK_DATA));
    skb_reset_network_header(skb);
    skb_set_transport_header(skb, udphoff);  

    newip = ip_hdr(skb);
    newudp = udp_hdr(skb);

    dsphdr = (ST_DSP_SOCK_DATA*)(newudp + 1);
    //����ͷ����Ϣ
    memmove((__u8*)newip, (__u8*)ip, udphoff);
    memmove((__u8*)newudp, (__u8*)udp, sizeof(struct udphdr));

    //���dspͨ����Ϣ
    dsphdr->usChan = fwconn->chan_id;
    if (connid & 0x1)
    {
        /* rtcp rx */
        dsphdr->usType = 6;
    }
    else
    {
        /* rtp rx */
        dsphdr->usType = 3;
    }
    dsphdr->usLength = ntohs(newudp->len) - sizeof(struct udphdr);

    #if RTP_DPS_MULTI_SOCKET
    //newudp->dest =   htons(18000 + (dsphdr->usChan/64));
    //newudp->source = htons(19000 + (dsphdr->usChan/64));
    newudp->dest =   htons(18000 + (dsphdr->usChan >> 6));
    newudp->source = htons(19000 + (dsphdr->usChan >> 6));
    #else
    newudp->dest = htons(8090);
    newudp->source = htons(8092);
    #endif
    newudp->len = htons(ntohs(newudp->len) + sizeof(ST_DSP_SOCK_DATA));

    newip->tot_len = htons(ntohs(newip->tot_len) + sizeof(ST_DSP_SOCK_DATA));
    //newip->saddr = in_aton("127.0.0.1");
    //newip->daddr = in_aton("127.0.0.1");
    newip->saddr = RTP_INADDR_LOOPBACK;
    newip->daddr = newip->saddr;

    #if 1
    newudp->check = CHECKSUM_NONE;
    skb->ip_summed = CHECKSUM_NONE;
    newip->check = CHECKSUM_NONE;
    #else
    newudp->check = 0;
    //���¼���У���
    skb->csum = 0;
    skb->csum = skb_checksum(skb, udphoff, skb->len - udphoff, 0);
    newudp->check = csum_tcpudp_magic (newip->saddr, newip->daddr, skb->len - udphoff, IPPROTO_UDP, skb->csum);

    skb->ip_summed = CHECKSUM_NONE;
    if (0 == newudp->check)
    {
	    newudp->check = CSUM_MANGLED_0;
    }
    newip->check = ip_fast_csum((unsigned char *)newip, newip->ihl);
    #endif

    return 0;
}

/* ����rtpת������ */
static struct rtp_media *rtp_relay_match_conn_v4(
            struct sk_buff *skb,
            struct iphdr *iph, 
            struct udphdr *udph, 
            struct rtp_relay_cache *cache, 
            unsigned int connid)
{
    struct ethhdr *ethh = eth_hdr(skb);
    struct rtphdr *rtph;
    struct rtcphdr *rtcph;
    struct tcphdr  *tcph;
    unsigned char proto ;
    __be16 source;
    __be16 dest;
    if(iph->protocol == IPPROTO_TCP)
    {
        proto = IPPROTO_TCP;
        tcph = tcp_hdr(skb);
        source = tcph->source;
        dest = tcph->dest;
    }
    else
    {
        proto = IPPROTO_UDP;
        source = udph->source;
        dest = udph->dest;
    }
    /* ý��˨���� */
    if (cache->aconn.ip_type == PF_INET)
    {
        /* media lock mode 1(half safe): will locked forward table bypass 30 packets */
        if (cache->aconn.media_lock == 1)
        {
            /* match return 1 */
            if (rtp_media_lock_match_v4(ethh, iph, udph, &cache->aconn))
            {
                /* ֻƥ��aconn */
                if (cache->bconn.ip_type != PF_INET)
                {
                    return &cache->bconn;
                }

                /* ����������ͺ�������ͬһ���߼��ӿ��� */
                if (rtp_media_lock_match_v4(ethh, iph, udph, &cache->bconn))
                {
                    /* ��aconn��bconn��һ�������˾�̬���� */
                    if (cache->bconn.media_lock == 0)
                    {
                        if ((iph->daddr == cache->bconn.local_ip.ip) &&
                            (iph->saddr == cache->bconn.remote_ip.ip) &&
                            (source == cache->bconn.remote_port))
                        {
                            /* match bconn. return aconn */
                            return &cache->aconn;
                        }
                        return &cache->bconn;
                    }
                    
                    if (connid & 0x1)
                    {
                        if ((cache->aconn.orig_remote_ip.ip == iph->saddr) && 
                            (cache->bconn.orig_remote_ip.ip != iph->saddr))
                        {
                            return &cache->bconn;
                        }
                        if ((cache->bconn.orig_remote_ip.ip == iph->saddr) && 
                            (cache->aconn.orig_remote_ip.ip != iph->saddr))
                        {
                            return &cache->aconn;
                        }
                        
                        /* rtcp packet */
                        if((cache->aconn.media_type != RM_MEDIA_APPLICATION) && (proto == IPPROTO_UDP))
                        {
                        rtcph = (struct rtcphdr *)(udph + 1);
                        }
                        if (cache->aconn.remote_ip.ip == iph->saddr)
                        {
                            return &cache->bconn;
                        }
                        else if (cache->bconn.remote_ip.ip == iph->saddr)
                        {
                            return &cache->aconn;
                        }
                        return NULL;
                    }
                    else
                    {
                        /* ��ͨת������û��rtpͷ�����ܶԱ�rtpͷ��Ϣ*/
                        if((cache->aconn.media_type != RM_MEDIA_APPLICATION) && (proto == IPPROTO_UDP))
                        {
                        /*���治��rtp��������ָ���Ǵ���ʱ�����ܶԱ�rtpͷ��Ϣ*/
                        if(RM_MEDIA_IMAGE != cache->aconn.media_type)
                        {
                            /* rtp packet */
                            rtph = (struct rtphdr *)(udph + 1);
                            if (rtph->rtp_paytype != cache->aconn.media_data.rtp.payload)
                            {
                                return &cache->aconn;
                            }
                            if (rtph->rtp_paytype != cache->bconn.media_data.rtp.payload)
                            {
                                return &cache->bconn;
                            }
                        }
                        }

                        if ((cache->aconn.orig_remote_ip.ip == iph->saddr) && 
                            (cache->bconn.orig_remote_ip.ip != iph->saddr))
                        {
                            return &cache->bconn;
                        }
                        if ((cache->bconn.orig_remote_ip.ip == iph->saddr) && 
                            (cache->aconn.orig_remote_ip.ip != iph->saddr))
                        {
                            return &cache->aconn;
                        }
                    }

                    if (cache->aconn.remote_port == 0)
                    {
                        /* ����ת������ */
                        //cache->aconn.remote_port = udph->source;
                        //cache->aconn.remote_ip.ip = iph->saddr;
                        #if 0
                        if((cache->aconn.media_type != RM_MEDIA_APPLICATION) && (proto == IPPROTO_UDP))
                        {
                            g_rtp_ctrl_tbl[0][connid + 1].cache->aconn.remote_ip.ip = iph->saddr;
                        }
                        //g_rtp_ctrl_tbl[connid + 1].cache->aconn.remote_port = udph->source;
                         #endif
                        return &cache->bconn;
                    }
                    else
                    {
                        if ((cache->aconn.remote_ip.ip == iph->saddr) && 
                            (cache->aconn.remote_port == source))
                        {
                            return &cache->bconn;
                        }
                    }

                    if (cache->bconn.remote_port == 0)
                    {
                        /* ����ת������ */
                        //cache->bconn.remote_port = udph->source;
                        //cache->bconn.remote_ip.ip = iph->saddr;
                        #if 0
                        if((cache->aconn.media_type != RM_MEDIA_APPLICATION) && (proto == IPPROTO_UDP))
                        {
                            g_rtp_ctrl_tbl[0][connid + 1].cache->bconn.remote_ip.ip = iph->saddr;
                        }
                        //g_rtp_ctrl_tbl[connid + 1].cache->bconn.remote_port = udph->source;
                        #endif
                        return &cache->aconn;
                    }
                    else
                    {
                        if ((cache->bconn.remote_ip.ip == iph->saddr) && 
                            (cache->bconn.remote_port == source))
                        {
                            return &cache->aconn;
                        }
                    }
                 
                    return &cache->bconn;
                }
                
                /* media lock match */
                return &cache->bconn;
            }
        }

        /* media lock mode 2(unsafe): bypass all packet and update forward table */
        if (cache->aconn.media_lock == 2)
        {
            if (iph->daddr == cache->aconn.local_ip.ip)
            {
                /* ����������ͺ�������ͬһ���߼��ӿ��� */
                if (iph->daddr == cache->bconn.local_ip.ip)
                {
                    if ((iph->saddr == cache->bconn.remote_ip.ip) &&
                        (source == cache->bconn.remote_port))
                    {
                        /* match bconn. return aconn */
                        return &cache->aconn;
                    }
                }
                
                /* ý��˨�����Ƶ�rtp���ĺϷ��Լ��� */
                #if 0
                if (cache->aconn.remote_ip.ip != iph->saddr)
                {
                    cache->aconn.remote_ip.ip = iph->saddr;
                    if (likely(ethh))
                    {
                        memcpy(cache->aconn.remote_mac, ethh->h_source, ETH_ALEN);
                    }
                }
                if (cache->aconn.remote_port != udph->source)
                {
                    cache->aconn.remote_port = udph->source;
                }
                #endif
                
                return &cache->bconn;
            }
        }

        /* media lock mode 0(safe): strict match the forward table */
        if ((iph->daddr == cache->aconn.local_ip.ip) &&
            (iph->saddr == cache->aconn.remote_ip.ip) &&
            (source == cache->aconn.remote_port))
        {
            /* match cache
            if (iph->saddr == g_debug_enable)
            {
                (void)rtp_packet_dump_limit(skb);
            }*/
            
            /* ƥ��a���ӵı��ģ�ʹ��b����ת�� */
            return &cache->bconn;
        }
    }
    
    if (cache->bconn.ip_type == PF_INET)
    {
        /* media lock mode 1(half safe): will locked forward table bypass 30 packets */
        if (cache->bconn.media_lock == 1)
        {
            /* match return 1 */
            if (rtp_media_lock_match_v4(ethh, iph, udph, &cache->bconn))
            {
                /* media lock match */
                return &cache->aconn;
            }
        }

        /* media lock mode 2(unsafe): bypass all packet and update forward table */
        if (cache->bconn.media_lock == 2)
        {
            if (iph->daddr == cache->bconn.local_ip.ip)
            {
                /* ý��˨�����Ƶ�rtp���ĺϷ��Լ��� */
                #if 0
                if (cache->bconn.remote_ip.ip != iph->saddr)
                {
                    cache->bconn.remote_ip.ip = iph->saddr;
                    if (likely(ethh))
                    {
                        memcpy(cache->bconn.remote_mac, ethh->h_source, ETH_ALEN);
                    }
                }
                if (cache->bconn.remote_port != udph->source)
                {
                    cache->bconn.remote_port = udph->source;
                }
                #endif
                
                return &cache->aconn;
            }
        }

        /* media lock mode 0(safe): strict match the forward table */
        if ((iph->daddr == cache->bconn.local_ip.ip) &&
            (iph->saddr == cache->bconn.remote_ip.ip) &&
            (source == cache->bconn.remote_port))
        {
            /* match cache 
            if (iph->saddr == g_debug_enable)
            {
                (void)rtp_packet_dump_limit(skb);
            }*/
            
            /* ƥ��b���ӵı��ģ�ʹ��a����ת�� */
            return &cache->aconn;
        }
    }

    return NULL;
}

/* RTCP���ĺϷ��Լ�飬�Ϸ�����0 */
static int rtp_relay_rtcp_check_v4(struct udphdr *udph, rtcp_t *rtcph)
{
    if (udph->len < (sizeof(struct udphdr) + sizeof(rtcp_t)))
    {
        /* �Ƿ�rtcp */
        hook_debug("rtcp packet udph len(%d) invalid. drop.\r\n", udph->len);
        return -1;
    }
    
    if (rtcph->common.version != 2)
    {
        hook_debug("rtcp packet version(%d) invalid. drop.\r\n", rtcph->common.version);
        return -1;
    }

    if ((rtcph->common.pt < RTCP_SR) || (rtcph->common.pt > RTCP_APP))
    {
        hook_debug("rtcp packet payload type(%d) invalid. drop.\r\n", rtcph->common.pt);
        return -1;
    }

    return 0;
}

static void rtp_media_lock_exchange(struct rtp_media *conn)
{
    __be16              port; 
    unsigned char       mac[ETH_ALEN];
    union rtp_inet_addr ip;

    port = conn->remote_port;
    conn->remote_port = conn->ref_conn->remote_port;
    conn->ref_conn->remote_port = port;

    ip.in6 = conn->remote_ip.in6;
    conn->remote_ip.in6 = conn->ref_conn->remote_ip.in6;
    conn->ref_conn->remote_ip.in6 = ip.in6;

    memcpy(mac, conn->remote_mac, ETH_ALEN);
    memcpy(conn->remote_mac, conn->ref_conn->remote_mac, ETH_ALEN);
    memcpy(conn->ref_conn->remote_mac, mac, ETH_ALEN);

    return;
}

/* rfc2833 log */
static int rtp_relay_log_rfc2833_v4(struct iphdr *iph,struct udphdr *udph, struct rtphdr *rtph, struct rtp_media *fw_conn)
{
    struct rfc2833hdr *rfc2833h = NULL;
         
     if (htons(udph->len) != (sizeof(struct udphdr) + sizeof(struct rtphdr) + sizeof(struct rfc2833hdr)))
     {       
         return -3;
     }
     
    rfc2833h = (struct rfc2833hdr *)(rtph + 1);
    if(rfc2833h != NULL)
    {
        log_debug("rfc2833 event_id :%u,flag :%u,event_duration :%u, media_lock :%u,ip.saddr: %d:%d:%d:%d:%hu,ip.daddr: %d:%d:%d:%d:%hu \r\n",
        rfc2833h->event_id,rfc2833h->flag,ntohs(rfc2833h->event_duration),fw_conn->media_lock,
        NIPQUAD(iph->saddr),ntohs(udph->source),NIPQUAD(iph->daddr),ntohs(udph->dest));
        rfc2833h = NULL;
        return 0;
    }
    else
    {
        log_debug("rfc2833 header null \r\n");
        
    return 0;
}
}

/* rfc2833����ͷ�Ϸ��Լ�� */
static int rtp_relay_rfc2833_check_v4(struct udphdr *udph, struct rtphdr *rtph, struct rtp_media *fw_conn)
{
    #ifdef RTP_DSP_TEST_MODE
    return 0;
    #endif
    unsigned int rfc2833;
    __u8         dscp;
    
    if (htons(udph->len) != (sizeof(struct udphdr) + sizeof(struct rtphdr) + sizeof(struct rfc2833hdr)))
    {
        hook_debug("rtp packet dtmf len(%d!=%d) invalid. drop.\r\n", htons(udph->len), 
                    (sizeof(struct udphdr) + sizeof(struct rtphdr) + sizeof(struct rfc2833hdr)));
        return -3;
    }
    
    /* ȡ��rfc2833��payload type��� */
    #if 0
    if ((fw_conn->media_data.rtp.rfc2833) && (fw_conn->media_data.rtp.rfc2833 != rtph->rtp_paytype))
    {
        hook_debug("rtp packet dtmf type %d, must be %d, invalid. drop.\r\n", rtph->rtp_paytype, 
                    fw_conn->media_data.rtp.rfc2833);
        return -1;
    }
    #endif

    /* �����ڽ������ͺ�������ͬһ�߼��ӿ��ϣ��Ҵ���ý��������� */
    if (fw_conn->media_sync_flag && (fw_conn->media_lock == 0) && (fw_conn->chan_id < 0))
    {
        if ((fw_conn->ip_type == fw_conn->ref_conn->ip_type) && 
            (fw_conn->media_data.rtp.rfc2833_remote) &&
            (fw_conn->media_data.rtp.rfc2833_remote != rtph->rtp_paytype) &&
            (fw_conn->ref_conn->media_data.rtp.rfc2833_remote) &&
            (fw_conn->ref_conn->media_data.rtp.rfc2833_remote == rtph->rtp_paytype))
        {
            /* exchange rfc2833 */
            rfc2833 = fw_conn->media_data.rtp.rfc2833;
            fw_conn->media_data.rtp.rfc2833 = fw_conn->ref_conn->media_data.rtp.rfc2833;
            fw_conn->ref_conn->media_data.rtp.rfc2833 = rfc2833;

            /* exchange rfc2833 remote */
            rfc2833 = fw_conn->media_data.rtp.rfc2833_remote;
            fw_conn->media_data.rtp.rfc2833_remote = fw_conn->ref_conn->media_data.rtp.rfc2833_remote;
            fw_conn->ref_conn->media_data.rtp.rfc2833_remote = rfc2833;
            fw_conn->media_sync_flag = 0;

            dscp = fw_conn->dscp;
            fw_conn->dscp = fw_conn->ref_conn->dscp;
            fw_conn->ref_conn->dscp = dscp;

            hook_debug("media lock rfc2833 rollback. aconn:%u-->%u, %u-->%u. \n", 
                        fw_conn->ref_conn->media_data.rtp.rfc2833, fw_conn->media_data.rtp.rfc2833, 
                        fw_conn->ref_conn->media_data.rtp.rfc2833_remote, fw_conn->media_data.rtp.rfc2833_remote);
        }
    }

    return 0;
}

/* RTP���ĺϷ��Լ�飬�Ϸ�����0 */
static int rtp_relay_check_packet_v4(struct udphdr *udph, struct rtphdr *rtph, struct rtp_media *fw_conn)
{
    if (udph->len <= (sizeof(struct udphdr) + sizeof(struct rtphdr)))
    {
        /* rtp�����غ�Ϊ0 */
        hook_debug("rtp packet udph->len(%d) invalid. drop.\n", udph->len);
        return -1;
    }

    if (rtph->rtp_version != 2)
    {
        hook_debug("rtp packet version(%d) invalid. drop.\n", rtph->rtp_version);
        return -2;
    }

    if (rtph->rtp_paytype != fw_conn->media_data.rtp.payload)
    {
        hook_debug("packet payload type:%d, rtp payload:%d, rfc2833:%d. \n", 
                    rtph->rtp_paytype, fw_conn->media_data.rtp.payload, fw_conn->media_data.rtp.rfc2833);
        
        /* ��ƥ��payload type������£��ж��Ƿ���dtmf���� */
        return rtp_relay_rfc2833_check_v4(udph, rtph, fw_conn); 
    }

    /* ʵ��׶��ȷ��ɶԱ����غɳ��ȼ�� */
    #if 0
    if ((rtph->rtp_extbit == 0) && 
        (rtph->rtp_padbit == 0) && 
        (htons(udph->len) > fw_conn->media_data.rtp.max_psize))
    {
        /* �������ʵ�ʵĴ������С */
        hook_debug("rtp packet size invalid real:%d, expect:%d. drop.\r\n", htons(udph->len), fw_conn->media_data.rtp.max_psize);
        return -1;
    }
    #endif
    
    return 0;
}

/* rtpת�����ݰ�ipv4��ipv6�������޸Ĳ��� */
static void rtp_relay_update_packet_v4tov6(struct sk_buff *skb, 
            struct iphdr *iph, 
            struct udphdr *udph, 
            struct rtp_media *fw_conn)
{

    return;
}

/* ����ip���ݰ���dscp��־ */
static void rtp_relay_update_dscp_v4(struct iphdr *iph, __u8 dscp)
{
    u_int8_t dscp_val = iph->tos >> DDOS_DSCP_SHIFT;

	if (dscp != dscp_val) {
		ipv4_change_dsfield(iph, (__u8)(~DDOS_DSCP_MASK), dscp << DDOS_DSCP_SHIFT);
	}

    return;
}

/* ���ip���ݰ���vlan tag��Ϣ */
static inline int rtp_relay_vlan_insert_tag(struct sk_buff *skb, u16 connid, u16 vlan_tci)
{
    if (g_debug_conn_enable == connid)
    {
        hook_info("set vlan id:%d \n", vlan_tci);
    }
    
    #if 1
    
    __vlan_hwaccel_put_tag(skb, vlan_tci);
    
    #else
    
	struct vlan_ethhdr *veth;

    if (skb_headroom(skb) < VLAN_HLEN)
    {
        hook_debug("ERROR: no space to extend 802.1q vlan head. \n");

        return -1;
    }
    
	veth = (struct vlan_ethhdr *)skb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);
	skb->mac_header -= VLAN_HLEN;

	/* first, the ethernet type */
	veth->h_vlan_proto = htons(ETH_P_8021Q);

	/* now, the TCI */
	veth->h_vlan_TCI = htons(vlan_tci);
    
    #endif

	return 0;
}

/* ����rtp��ת��ת�����ݱ���ͷ�� */
static int rtp_relay_update_packet_v4(struct sk_buff *skb, 
            struct iphdr *iph, 
            struct udphdr *udph, 
            struct rtp_media *fw_conn)
{
    struct ethhdr *ethh;
    __u16 udp_len;
    struct rtphdr *rtph;
    struct tcphdr *tcph;
    unsigned int tot_len;
    unsigned int iph_len;
    
    tot_len = ntohs(iph->tot_len);
    iph_len = ip_hdrlen(skb);    
    if(iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);
    }

    /* �޸�ip����ͷ����ת�� */
    iph->saddr = fw_conn->local_ip.ip;
    if (fw_conn->remote_ip.ip)
    {
        iph->daddr = fw_conn->remote_ip.ip;
    }
    else
    {
        iph->daddr = fw_conn->orig_remote_ip.ip;
    }
    
    
    /* �޸�dscp */
    #if 1
    iph->tos = ((fw_conn->dscp) << DDOS_DSCP_SHIFT);
    #else
    iph->tos = 0;
    if (fw_conn->dscp)
    {
        rtp_relay_update_dscp_v4(iph, fw_conn->dscp);
    }
    #endif
    iph->check = 0;
    if(iph->protocol == IPPROTO_UDP)
    {
    udph->source = fw_conn->local_port;
    }
    else 
    {
        tcph->source = fw_conn->local_port;
    }
    /*��Щ�豸���ܷ��͵Ķ˿ںźͽ��ն˿ںŲ�һ�£���ip�����ܳ��֣�������豸����������phoneҲ����
      �Խ�*/
    if (likely(!(fw_conn->flag & KERNEL_ONLY_USE_ORIG_FOR_SEND)) && fw_conn->remote_port)
    {
        if(iph->protocol == IPPROTO_UDP)
        {
        udph->dest = fw_conn->remote_port;
    }
    else
    {
            tcph->dest = fw_conn->remote_port;
        }
    }
    else
    {
        if(iph->protocol == IPPROTO_UDP)
        {
        udph->dest = fw_conn->orig_remote_port;
    }
        else
        {
            tcph->dest = fw_conn->orig_remote_port;
        }
    }

    if((iph->protocol == IPPROTO_UDP) && (fw_conn->media_type != RM_MEDIA_APPLICATION))
    {
    /* rtp�����غɵ�dtmf rfc2833ת�� */
    if (!(htons(fw_conn->ref_conn->local_port) & 0x1))
    {
        rtph = (struct rtphdr *)(udph + 1);     
        
        if ((fw_conn->media_data.rtp.rfc2833) &&
            (rtph->rtp_paytype != fw_conn->media_data.rtp.payload) &&
            (htons(udph->len) == (sizeof(struct udphdr) + sizeof(struct rtphdr) + sizeof(struct rfc2833hdr))))
        {
            hook_debug("timestamp:%lld, transform rfc2833(%d.%d.%d.%d->%d.%d.%d.%d) %u->%u \n", 
                        ktime_to_ms(skb->tstamp),
                        NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), 
                        rtph->rtp_paytype, fw_conn->media_data.rtp.rfc2833);

            if (rtph->rtp_paytype != fw_conn->media_data.rtp.rfc2833)
            {
                rtph->rtp_paytype = fw_conn->media_data.rtp.rfc2833;
            }
        }
    }
    }
    if(iph->protocol == IPPROTO_UDP)
    {
    udph->check = 0; 
    udp_len = ntohs(udph->len);                               
    skb->csum = csum_partial(skb_transport_header(skb), udp_len, 0);
    udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, udp_len, IPPROTO_UDP, skb->csum);
    skb->ip_summed = CHECKSUM_NONE;
    if (0 == udph->check)
    {
	    udph->check = CSUM_MANGLED_0;
    }
    }
    else
    {
        /* tcp */
        tcph->check = 0; 
        skb->csum = csum_partial(skb_transport_header(skb), tot_len-iph_len, 0);
        tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, tot_len-iph_len, IPPROTO_TCP, skb->csum);
        skb->ip_summed = CHECKSUM_NONE;
        if (0 == tcph->check)
        {
            tcph->check = CSUM_MANGLED_0;
        }

    }
    iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
    
    ethh = eth_hdr(skb);
    memcpy(ethh->h_source, fw_conn->local_mac, ETH_ALEN);
    memcpy(ethh->h_dest, fw_conn->remote_mac, ETH_ALEN);

    skb->dev = fw_conn->dev;
    skb_push(skb, sizeof(struct ethhdr));

    /* vlan */
    if (fw_conn->vlanid & VLAN_VID_MASK)
    {
        return rtp_relay_vlan_insert_tag(skb, htons(fw_conn->local_port), fw_conn->vlanid);
    }
    
    /* dev_queue_xmit(skb); */

    return 0;
}

/* DTLS����ת�������ذ崦����� */
static int rtp_relay_dtls_redirect_v4(struct sk_buff *skb)
{
    struct ethhdr *ethh = eth_hdr(skb);

    if (!ethh)
    {
        return -1;
    }
    
    memcpy(ethh->h_dest, g_dtsl_redirect_mac, ETH_ALEN);
    skb_push(skb, sizeof(struct ethhdr));

    skb->dev = dev_get_by_name(&init_net, "eth0");;
    
    dev_queue_xmit(skb);

    return 0;
}

static int rtp_relay_redirect(struct sk_buff *skb)
{
    struct ethhdr *ethh = eth_hdr(skb);

    if (!ethh)
    {
        return -1;
    }
    
    memcpy(ethh->h_dest, g_broadcast_mac, ETH_ALEN);

    skb->dev = dev_get_by_name(&init_net, "eth0");;
    
    dev_queue_xmit(skb);

    return 0;
}

/*
 * ��ȡRTPý�屨�Ĵ���, ������LAN����WAN��ִ����ͬ����
 * register PRE-ROUTING 
 */
static unsigned int rtp_relay_input_hook_v4(unsigned int hook,
			struct sk_buff *skb,
			const struct net_device *in,
			const struct net_device *out,
			int (*okfn)(struct sk_buff *))
{
    struct iphdr    *iph = NULL;
    struct udphdr   *udph = NULL;
    struct tcphdr   *tcph = NULL;
    __u16   dport;
    __u16   sport;
    struct rtp_media *fw_conn;
    rtcp_t *rtcph;
    struct rtphdr *rtph;
    int ret;
    #ifdef RTP_PACKET_TIME_DELAY
    unsigned long last_rx;
    unsigned long delay_rx;
    unsigned int  delay_pktin_rx;
    unsigned int  delay_times;
    struct rtphdr *rtph_delay;
    #endif
    unsigned int srtp_type;
    unsigned char *dtls_type;
    unsigned char proto;
    struct rtp_ctrl_tbl *ctrl_tbl;
    struct sk_buff *skb_cp;
    iph = ip_hdr(skb);
    if (unlikely(!iph))
    {
        return NF_ACCEPT;
    }
///-
    if(unlikely(iph->ihl != 5))
    {
        return NF_ACCEPT;
    }
    if(unlikely(iph->frag_off & htons(IP_MF)))
    {
        return NF_DROP;
    }
    skb_set_transport_header(skb, (iph->ihl *4));

    /* ����127.x.x.x �� 0.0.0.0 �����ݱ��� */
    if ((NIP1(iph->saddr) == 127) || (iph->saddr == 0))
    {
        return NF_ACCEPT;
    }

    #ifndef RTP_DSP_TEST_MODE
    /* 10.251.x.x ����Ϊ�豸�ڲ�ͨ�ű��ģ�ֱ�ӷ��в������� */
    if ((NIP1(iph->saddr) == 10) && (NIP2(iph->saddr) == 251))
    {
        return NF_ACCEPT;
    }
    #endif
    
    if ((iph->protocol != IPPROTO_UDP) && (iph->protocol != IPPROTO_TCP))
    {
        /*
         * relay_rtp_ddos_detect(skb); ���ɰ�ȫģ�鴦��
         */
        return NF_ACCEPT;
    }

    if(iph->protocol == IPPROTO_UDP)
    {
        proto = IPPROTO_UDP;
    udph = udp_hdr(skb);
        dport = ntohs(udph->dest);
        sport = ntohs(udph->source);
    }
    else
    {
        proto = IPPROTO_TCP;
        tcph = tcp_hdr(skb);
        dport = ntohs(tcph->dest);
        sport = ntohs(tcph->source);
    }
    //printk("<1> port:%u, cpuid:%u \n", dport, smp_processor_id());

    /*hook_debug("sip:%d.%d.%d.%d:%d, dstip:%d.%d.%d.%d:%d.\r\n", 
                NIPQUAD(iph->saddr), sport, 
                NIPQUAD(iph->daddr), dport);*/
    
    if(proto == IPPROTO_UDP)
    {
        ctrl_tbl = &g_rtp_ctrl_tbl[0][dport];
    }
    else
    {
        /* tcp */
        ctrl_tbl = &g_rtp_ctrl_tbl[1][dport];
    }
    rtp_read_lock(&ctrl_tbl->lock);   
    if (ctrl_tbl->cache != NULL)
    {
        /* ����Ƿ�ƥ��ת������ */
        fw_conn = rtp_relay_match_conn_v4(skb, iph, udph, ctrl_tbl->cache, dport);
        if (!fw_conn)
        {
            /*
             * relay_rtp_ddos_detect(skb); ���ɰ�ȫģ�鴦��
             */
            rtp_read_unlock(&ctrl_tbl->lock);

            if (g_debug_enable == 8)
            {
                hook_info("not match forward table cache(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return accept. \n", 
                            NIPQUAD(iph->saddr), sport, 
                            NIPQUAD(iph->daddr), dport);
            }
            if (g_debug_enable == 101)
            {
                hook_info("not match forward table cache(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return accept. \n", 
                            NIPQUAD(iph->saddr), sport, 
                            NIPQUAD(iph->daddr), dport);
            }
            
            return NF_ACCEPT;
        }

        /* ����rtp/rtcp ���ģ�����udp���ģ���ý�����Ͳ�Ϊapplication */
        if((proto == IPPROTO_UDP) && (fw_conn->media_type != RM_MEDIA_APPLICATION))
        {     
        srtp_type = fw_conn->media_data.rtp.srtp;

        /*����ʹ�õĶ˿���ż������rtcp��ʹ�������˿�*/
        if (unlikely(dport & 0x1))
        {   
            /* webRTC dtls packet, redirect to control board */
            //if (srtp_type == 2)
            {
                dtls_type = (unsigned char *)(udph + 1);
                if (((*dtls_type > 19) && (*dtls_type <= 64)) ||
                    (*dtls_type < 2))
                {
                            rtp_read_unlock(&ctrl_tbl->lock);
                    if (rtp_relay_dtls_redirect_v4(skb) == 0)
                    {
                        /* redirect success */
                                if (g_debug_enable == 101)
                                {
                                    hook_info("not match forward table cache(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return stolen. \n", 
                                    NIPQUAD(iph->saddr), sport, 
                                    NIPQUAD(iph->daddr), dport);
                                }                                
                        return NF_STOLEN;
                    }
                    else
                    {
                        hook_debug("redirect dtls/stun packet(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d) fail. \n", 
                                    NIPQUAD(iph->saddr), htons(udph->source), 
                                    NIPQUAD(iph->daddr), htons(udph->dest));
                        return NF_ACCEPT;
                    }
                }
            }
            
            /* rtcp ���Ĵ��� */
            rtcph = (rtcp_t *)(udph + 1);
            if (rtp_relay_rtcp_check_v4(udph, rtcph))
            {
                /* �Ƿ�rtcp���� */
                fw_conn->ref_conn->statis.recvpkts_err++;
                fw_conn->ref_conn->statis.recvbytes_err += htons(iph->tot_len);
                        rtp_read_unlock(&ctrl_tbl->lock);

                        hook_debug("error: invalid rtcp packet(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return accept. \n", 
                            NIPQUAD(iph->saddr), htons(udph->source), 
                            NIPQUAD(iph->daddr), htons(udph->dest));

                /*
                 * relay_rtp_ddos_detect(skb); ���ɰ�ȫģ�鴦��
                 */
                return NF_ACCEPT;
            }
            
            switch (rtcph->common.pt)
            {
                case RTCP_RR:
                    /* ����rtcpͳ����Ϣ */
                    fw_conn->ref_conn->statis.rtcp.fraction_lost = rtcph->r.rr.rr[1].fract_lost;
                    fw_conn->ref_conn->statis.rtcp.jitter = htonl(rtcph->r.rr.rr[1].jitter);
                    fw_conn->ref_conn->statis.rtcp.lost_pkts = 
                            (rtcph->r.rr.rr[1].total_lost_h8 << 16) + htons(rtcph->r.rr.rr[1].total_lost_l16);

                    hook_debug("fraction_lost:%d, jitter:%d, lost_pkts:%d.%d\r\n", rtcph->r.rr.rr[1].fract_lost,
                            htonl(rtcph->r.rr.rr[1].jitter), rtcph->r.rr.rr[1].total_lost_h8, htons(rtcph->r.rr.rr[1].total_lost_l16));
                    break;
                    
                case RTCP_SR:
                    fw_conn->ref_conn->statis.rtcp.sender_pkts = htonl(rtcph->r.sr.sr.sender_pcount);
                    //hook_debug("sender_pcount:%u\r\n", htonl(rtcph->r.sr.sr.sender_pcount));
                    break;

                default:
                    break;
            }
        }
        else
        {
            /* webRTC dtls packet, redirect to control board */
            /*���治��rtp���������Ϸ��Լ��*/
            if(RM_MEDIA_IMAGE != fw_conn->media_type)
            {
                //if (srtp_type == 2)
                {
                    dtls_type = (unsigned char *)(udph + 1);
                    if (((*dtls_type > 19) && (*dtls_type <= 64)) ||
                        (*dtls_type < 2))
                    {
                                rtp_read_unlock(&ctrl_tbl->lock);
                        
                        if (rtp_relay_dtls_redirect_v4(skb) == 0)
                        {
                            /* redirect success */
                                    if (g_debug_enable == 101)
                                    {
                                        hook_info("not match forward table cache(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return stolen. \n", 
                                        NIPQUAD(iph->saddr), sport, 
                                        NIPQUAD(iph->daddr), dport);
                                    }  
                            return NF_STOLEN;
                        }
                        else
                        {
                                    hook_debug("redirect dtls/stun packet(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d) fail. return accept \n", 
                                        NIPQUAD(iph->saddr), htons(udph->source), 
                                        NIPQUAD(iph->daddr), htons(udph->dest));
                            return NF_ACCEPT;
                        }
                    }
                }
           
                rtph = (struct rtphdr *)(udph + 1);
                /* print rfc2833 info */
                if(g_rtp_log_enable)
                        {
                    rtp_relay_log_rfc2833_v4(iph,udph,rtph,fw_conn);
                        }
                /* send rfc2833 info to user */
                if(rtp_relay_is_rfc2833_match(udph,rtph))
                    rtp_netlink_send_rfc2833_report(rtph, iph, udph);
                    
                /* rtp���ĺϷ��Լ��, rtp_check_packet�Ϸ�����ֵΪ0 */
                if (g_rtp_check_enable && rtp_relay_check_packet_v4(udph, rtph, fw_conn->ref_conn))
                {
                    fw_conn->ref_conn->statis.recvpkts_err++;
                    fw_conn->ref_conn->statis.recvbytes_err += htons(iph->tot_len);
                    
                            rtp_read_unlock(&ctrl_tbl->lock);

                            hook_debug("error: invalid rtp packet(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return accept. \n", 
                                NIPQUAD(iph->saddr), htons(udph->source), 
                                NIPQUAD(iph->daddr), htons(udph->dest));

                    /*
                     * relay_rtp_ddos_detect(skb); ���ɰ�ȫģ�鴦��
                     */
                    return NF_ACCEPT;
                }

                #ifdef RTP_PACKET_TIME_DELAY
                if (g_rtp_delay_pkt_enable)
                {
                    delay_rx = htonl(rtph->rtp_timestamp);
                    if (!fw_conn->ref_conn->last_pktin_times)
                    {
                        fw_conn->ref_conn->last_pktin_times = delay_rx;
                    }
                    else
                    {
                        delay_pktin_rx = delay_rx - fw_conn->ref_conn->last_pktin_times;
                        if (delay_pktin_rx < fw_conn->ref_conn->delay_pktin_min)
                        {
                            fw_conn->ref_conn->delay_pktin_min = delay_pktin_rx;
                        }
                        if (delay_pktin_rx > fw_conn->ref_conn->delay_pktin_max)
                        {
                            fw_conn->ref_conn->delay_pktin_max = delay_pktin_rx;
                        }
                        if ((delay_pktin_rx > (fw_conn->ref_conn->media_data.rtp.max_ptime + g_rtp_delay_times)) || 
                            (delay_pktin_rx < (fw_conn->ref_conn->media_data.rtp.max_ptime - g_rtp_delay_times)))
                        {
                            fw_conn->ref_conn->delay_pktin++;
                        }
                        fw_conn->ref_conn->last_pktin_times = delay_rx;
                        fw_conn->ref_conn->delay_pktin_total += delay_pktin_rx;
                    }
                }
                
                #endif
            }

            /* RTPý����QoS���ư����ʴ��� */
            #ifndef RTP_DSP_TEST_MODE
            if (rtp_relay_qos_check(skb, fw_conn->ref_conn))
            {
                fw_conn->ref_conn->statis.recvpkts_err++;
                fw_conn->ref_conn->statis.recvbytes_err += htons(iph->tot_len);
                        rtp_read_unlock(&ctrl_tbl->lock);
                
                /* �������������������ƣ����� */
                        hook_debug("error: qos overflow. packet(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), return accept.\n", 
                                NIPQUAD(iph->saddr), htons(udph->source), 
                                NIPQUAD(iph->daddr), htons(udph->dest));
                
                /*
                 * relay_rtp_ddos_detect(skb); ���ɰ�ȫģ�鴦��
                 */
                return NF_ACCEPT;
            }
            #endif

            #ifdef RTP_PACKET_TIME_DELAY
            if (g_rtp_delay_enable)
            {
                if (!fw_conn->ref_conn->last_rx)
                {
                    fw_conn->ref_conn->last_rx = jiffies;
                }
                else
                {
                    last_rx = jiffies;
                    delay_rx = last_rx - fw_conn->ref_conn->last_rx;
                    if (fw_conn->ref_conn->delay_min > delay_rx)
                    {
                        fw_conn->ref_conn->delay_min = delay_rx;
                    }
                    if (fw_conn->ref_conn->delay_max < delay_rx)
                    {
                        fw_conn->ref_conn->delay_max = delay_rx;
                    }
                    if (delay_rx >= fw_conn->ref_conn->media_data.rtp.max_ptime)
                    {
                        delay_times = (delay_rx - fw_conn->ref_conn->media_data.rtp.max_ptime);
                    }
                    else 
                    {
                        delay_times = (fw_conn->ref_conn->media_data.rtp.max_ptime - delay_rx);
                    }
                    fw_conn->ref_conn->delay_total += delay_times;
                    if (delay_times > 2)
                    {
                        fw_conn->ref_conn->delay_2ms_pkts++;
                    }
                    if (delay_times > 8)
                    {
                        fw_conn->ref_conn->delay_8ms_pkts++;
                    }
                    
                    fw_conn->ref_conn->last_rx = last_rx;
                }
            }
            #endif

            #if 0
            if (g_debug_enable == 45)
            {
                if (rtp_relay_dtls_redirect_v4(skb) == 0)
                {
                    rtp_read_unlock(&g_rtp_ctrl_tbl[dport].lock);
                    /* redirect success */
                    return NF_STOLEN;
                }
            }
            #endif
        }
        
        /* rtp����ͳ�� */
        rtp_qos_rate_statis_v4(iph, fw_conn->ref_conn);
        }
        else
        {
            if(proto == IPPROTO_UDP)        
                hook_debug("bfcp packet, port: %u, len: %d \r\n", ntohs(fw_conn->local_port), ntohs(udph->len));
        }
        #ifdef RTP_DSP_TEST_MODE
        if (g_dsp_test_mode == 2)
        {
            rtp_read_unlock(&ctrl_tbl->lock);
            if(g_debug_enable == 101)
            {
                hook_info("g_dsp_test_mode, return drop \r\n");
            }

            return NF_DROP;
        }
        #endif

        /* ����ý���� */
        if (fw_conn->ref_conn->media_lock)
        {
            rtp_media_lock_update_v4(fw_conn->ref_conn->media_lock, fw_conn->ref_conn, eth_hdr(skb), iph, udph, dport, 
            skb);
        }

        /*��ָ��Ҫץ���Ķ˿ڵ����б��ĸ���һ�ݷ��͸����ذ�*/
        if(ctrl_tbl->captrue_flag)
        {
            skb_cp = skb_copy(skb, GFP_ATOMIC);
            if(skb_cp)
            {
                skb_push(skb_cp, sizeof(struct ethhdr));
                rtp_relay_redirect(skb_cp);
            }
            else
            {
                hook_info("port%u recv packet copy failed\n", dport);
            }
        }

        //printk("<1> port:%u, cpuid:%u \n", dport, smp_processor_id());
        /* RTPתDSP���� */
        if((fw_conn->media_type != RM_MEDIA_APPLICATION) && (iph->protocol == IPPROTO_UDP))
        {
        /* IPv4 RTP <--> DSP Process */
        if (fw_conn->ref_conn->chan_id >= 0)
        {
            /* ƥ��ԭʼ���� */
            if (rtp_relay_encode_rtp2dsp_v4(skb, fw_conn->ref_conn, dport) != 0)
            {
                fw_conn->ref_conn->statis.recvpkts_err++;
                fw_conn->ref_conn->statis.recvbytes_err += htons(iph->tot_len);
                    rtp_read_unlock(&ctrl_tbl->lock);

                    hook_debug("update dsp packet fail. return drop . \n");

                return NF_DROP;
            }

            /* ���·�������ͳ�� */
            fw_conn->ref_conn->statis.todspkts++;
            fw_conn->ref_conn->statis.todspbytes += htons(ip_hdr(skb)->tot_len);
            
                rtp_read_unlock(&ctrl_tbl->lock);
            
            if (!g_loopback_dst_entry)
            {
                if (ip_route_me_harder(skb, RTN_UNSPEC))
                {
                    hook_debug("Error: can't route rtp packet(%d.%d.%d.%d:%d->%d.%d.%d.%d:%d), drop. \n", 
                                NIPQUAD(iph->saddr), htons(udph->source), 
                                NIPQUAD(iph->daddr), htons(udph->dest));
                    return NF_DROP;
                }
                
                g_loopback_dst_entry = (struct dst_entry *)skb->_skb_refdst;
                dst_hold(skb_dst(skb));
                hook_debug("rtp2dsp dst_entry:%lu \n", (unsigned long)g_loopback_dst_entry);
            }
            
            /* ת����ȥ */
            skb->ip_summed = CHECKSUM_NONE;

            if (g_jitter_buffer_enable)
            {
                if (rtp_relay_jitter_buffer_add(skb, fw_conn->ref_conn->chan_id & RTP_DSP_CHAN_MASK) != 0)
                {
                    hook_debug("Error: add jitter buffer queue fail. drop packet. timestamp:%lld \n", ktime_to_ms(skb->tstamp));
                    return NF_DROP; 
                }
            }
            else
            {
                if (g_loopback_dst_entry)
                {
                    //skb_dst_drop(skb);
                    ip_send_check(ip_hdr(skb));
                    skb_dst_set(skb, g_loopback_dst_entry);
                    dst_hold(skb_dst(skb));
                    /* func ip_local_deliver(skb) */
                    dst_output(skb);
                }
                else
                {
                    ip_local_out(skb);
                }
            }
                if(g_debug_enable == 101)
                {
                    hook_info("send to dsp, return stolen \r\n");
                }                
            return NF_STOLEN;
        }
        }

        /* IPv4 RTP <--> IPv4 RTP Network */
        /* ���±��� */
        if (fw_conn->ip_type == PF_INET)
        {
            if (!rtp_relay_update_packet_v4(skb, iph, udph, fw_conn))
            {
                /*��ת�����͵ı���Ҳ����һ�ݷ��͸����ذ�*/
                if(ctrl_tbl->captrue_flag)
                {
                    rtp_read_unlock(&ctrl_tbl->lock);
                    skb_cp = skb_copy(skb, GFP_ATOMIC);
                    if(skb_cp)
                    {
                        rtp_relay_redirect(skb_cp);
                    }
                    else
                    {
                        hook_info("port%u send packet copy failed\n", dport);
                    }
                    rtp_read_lock(&ctrl_tbl->lock);
                }
                
                rtp_read_unlock(&ctrl_tbl->lock);
                /* ץ�� */
                if(iph->protocol == IPPROTO_UDP)
                {
                capture_match_and_send(skb,ntohs(udph->source),1,0);
                }
                else
                {
                    tcph = tcp_hdr(skb);
                    capture_match_and_send(skb,ntohs(tcph->source),1,0);                    
                }
                /*���Ŀ�ĺͱ���ĳ���ӿڵ�ip��ͬ��������Ҫ�ڱ��豸����תһ�Σ�ͨ��Ŀ�Ķ˿ں����ж���Ҫ�ڱ���ת����
                  ����Ҫ������һ���û��壬����Ǳ���ת����ֱ���ٵ�һ�κ���������ͨ�����ڵ�acl��������
                  ��cpu�ı��Ļ���*/
                if(iph->protocol == IPPROTO_UDP)
                {
                    if(unlikely((g_rtp_ctrl_tbl[0][ntohs(udph->dest)].cache &&
                        (iph->daddr == g_rtp_ctrl_tbl[0][ntohs(udph->dest)].cache->aconn.local_ip.ip ||
                        iph->daddr == g_rtp_ctrl_tbl[0][ntohs(udph->dest)].cache->bconn.local_ip.ip))))
                {
                    skb_pull(skb, sizeof(struct ethhdr));
                    rtp_relay_input_hook_v4(hook, skb, in, out, okfn);
                        if(g_debug_enable == 101)
                        {
                            hook_info("loopback, return stolen \r\n");
                        }                        
                        return NF_STOLEN;                        
                    }

                }
                else
                {
                    tcph = tcp_hdr(skb);
                    if(unlikely((g_rtp_ctrl_tbl[1][ntohs(tcph->dest)].cache &&
                        (iph->daddr == g_rtp_ctrl_tbl[1][ntohs(tcph->dest)].cache->aconn.local_ip.ip ||
                        iph->daddr == g_rtp_ctrl_tbl[1][ntohs(tcph->dest)].cache->bconn.local_ip.ip))))
                    {
                        skb_pull(skb, sizeof(struct ethhdr));
                        rtp_relay_input_hook_v4(hook, skb, in, out, okfn);
                        if(g_debug_enable == 101)
                        {
                            hook_info("loopback, return stolen \r\n");
                        }                        
                        return NF_STOLEN;
                    }
                }

                    ret = dev_queue_xmit(skb);
                    if (unlikely(ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN))
                    {
                        hook_debug("Error: connid %d, dev queue xmit packet fail.\n", dport);
                    /* rtp ����ͳ����Ϣ */
                    if((iph->protocol == IPPROTO_UDP) && (fw_conn->media_type != RM_MEDIA_APPLICATION))
                        {
                        rtp_read_lock(&ctrl_tbl->lock);
                        if (ctrl_tbl->cache != NULL)
                        {
                            if (fw_conn == &ctrl_tbl->cache->aconn)
                            {
                                fw_conn->ref_conn->statis.sendpkts_err++;
                            }
                            else if (fw_conn == &ctrl_tbl->cache->bconn)
                            {
                                fw_conn->ref_conn->statis.sendpkts_err++;
                            }
                        }
                        rtp_read_unlock(&ctrl_tbl->lock);
                    }
                }
                
                
                if(g_debug_enable == 101)
                {
                    hook_info("send out, return stolen \r\n");
                }                        
                return NF_STOLEN;
            }
            else
            {
                /* ����ʧ�ܣ�����ͳ����Ϣ */
                if((iph->protocol == IPPROTO_UDP) && (fw_conn->media_type != RM_MEDIA_APPLICATION))            
                {
                fw_conn->ref_conn->statis.recvpkts_err++;
                fw_conn->ref_conn->statis.recvbytes_err += htons(iph->tot_len);
                }
                rtp_read_unlock(&ctrl_tbl->lock);
                if(g_debug_enable == 101)
                {
                    hook_info("update packet fail, return drop \r\n");
                }                        
                return NF_DROP;
            }
        }
        
        /* IPv4 RTP <--> IPv6 RTP Network */
        if (fw_conn->ip_type == PF_INET6)
        {
            hook_debug("error: IPv6 not support, drop. \n");
            
            rtp_relay_update_packet_v4tov6(skb, iph, udph, fw_conn);
            
            //rtp_read_unlock(&g_rtp_ctrl_tbl[dport].lock);
            //dev_queue_xmit(skb);
            
            //return NF_STOLEN;
        }
    }
    
    rtp_read_unlock(&ctrl_tbl->lock);
    if(g_debug_enable == 101)
    {
        hook_info("media cache null, return accept \r\n");
    }
    
    /*
     * relay_rtp_ddos_detect(skb); ���ɰ�ȫģ�鴦��
     */
    return NF_ACCEPT;
}

/* move after ip_route_me_harder func  */
#if 0
static void rtp_relay_dst_entry_init(void)
{
    struct net *net = dev_net(dev_get_by_name(&init_net, "eth0"));
    struct rtable *rt;
    struct flowi4 fl4 = {};
    struct dst_entry *dst = NULL;

    g_dev_eth0 = dev_get_by_name(&init_net, "eth0");
    g_dev_loopback = dev_get_by_name(&init_net, "lo");

    hook_info("init loopback dst entry.\n");

    fl4.daddr = in_aton("127.0.0.1");
	fl4.saddr = in_aton("127.0.0.1");
	fl4.flowi4_tos = 0;
	fl4.flowi4_oif = 0;
	fl4.flowi4_mark = 0;
	fl4.flowi4_flags = 0;

    rt = ip_route_output_key(net, &fl4);
    if (IS_ERR(rt))
    {
        hook_info("init local host dst entry fail. \n");
        return;
    }

    g_loopback_dst_entry = &rt->dst;
    hook_info("dst entry:%lu \n", (unsigned long)g_loopback_dst_entry);
   

    return;
}
#endif

unsigned int rtp_relay_dsp_out_hook_v4(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
    struct iphdr  *ip=NULL, *newip = NULL;
    struct udphdr *udp=NULL, *newudp = NULL;
    struct ethhdr *eth;
    __u16  tblkey;
    struct rtp_media *fw_conn;
    int ret;
    
    int  fwd = 0;
    int udphoff = 0;
    __u32 chn = 0;
    ST_DSP_SOCK_DATA *dsphdr = NULL;
    struct sk_buff *skb_cp;

    ip = ip_hdr(skb);
    /* Netfilter LOCAL_IN���ӵı��Ĳ���ipͷ���ж� */
    #if 0
    if (!ip)
    {
        return NF_ACCEPT;
    }
    #endif
    
    if ((ip->ihl < 5) || (ntohs(ip->tot_len) > skb->len))
    {
        return NF_ACCEPT;
    }
    
    #ifndef RTP_DSP_TEST_MODE
    /* 10.251.x.x ����Ϊ�豸�ڲ�ͨ�ű��ģ�ֱ�ӷ��в������� */
    if ((NIP1(ip->saddr) == 10) && (NIP2(ip->saddr) == 251))
    {
        return NF_ACCEPT;
    }
    #endif

    if (ip->protocol != IPPROTO_UDP)
    {
        return NF_ACCEPT;
    }

    udphoff = ip_hdrlen(skb);
    skb_set_transport_header(skb, udphoff);	
    udp = udp_hdr(skb);
    if (!udp)
    {
        hook_info("udp hdr is null \n");
        return NF_ACCEPT;
    }

    #if RTP_DPS_MULTI_SOCKET
    if ((ip->saddr == RTP_INADDR_LOOPBACK) &&
        (ip->daddr == ip->saddr) &&
        (ntohs(udp->source) <= 18007) &&
        (ntohs(udp->source) >= 18000) &&
        (ntohs(udp->dest) <= 19007) &&
        (ntohs(udp->dest) >= 19000))
    #else
    if ((ntohs(udp->dest) == 8092) &&
        (ntohs(udp->source) == 8090)  &&
        (ip->daddr == ip->saddr)  &&
        (ip->saddr == RTP_INADDR_LOOPBACK))
    #endif
    {
        fwd = 1;
    }
    if (!fwd)
    {
        return NF_ACCEPT;
    }

    dsphdr = (ST_DSP_SOCK_DATA *)(udp + 1);
    chn = dsphdr->usChan;

    if (chn >= RTP_DSP_CHAN_MAX)
    {
        if (g_debug_enable)
        {
            if (net_ratelimit())
            {
                hook_info("DSP chanID(%d) invalid len:%d, type:%d, udp_len:%d\r\n", 
                    chn, dsphdr->usLength, dsphdr->usType, htons(udp->len));
            }
        }
        return NF_DROP;
    }
    
    /* check dsp packet */
    if (htons(udp->len) != (dsphdr->usLength + sizeof(ST_DSP_SOCK_DATA) + sizeof(struct udphdr)))
    {
        if (g_debug_enable)
        {
            if (net_ratelimit())
            {
                hook_info("DSP chanID(%d) invalid len:%d(+%d), type:%d, udp_len:%d\r\n", 
                    chn, dsphdr->usLength, sizeof(ST_DSP_SOCK_DATA), dsphdr->usType, htons(udp->len));
            }
        }
        return NF_DROP;
    }
    
    if (dsphdr->usType == 4)
    {
        /* rtp���� */
        tblkey = g_rtp_dsp_chan_entry[chn].connid;
    }
    else if (dsphdr->usType == 7)
    {
        /* rtcp���� */
        tblkey = g_rtp_dsp_chan_entry[chn].connid + 1;
    }
    else
    {
        hook_debug("dsp type:%d, chanid:%d, ignore and accept.\r\n", dsphdr->usType, chn);
        return NF_ACCEPT;
    }
    /* udp ת���� */
    rtp_read_lock(&g_rtp_ctrl_tbl[0][tblkey].lock);
    if (g_rtp_ctrl_tbl[0][tblkey].cache == NULL)
    {
        if (g_debug_enable)
        {
            if (net_ratelimit())
            {
                hook_info("ERROR: connection(%d)/chanid(%d) already died. drop packet.\r\n", tblkey, chn);
            }
        }
        /* dspת�������ı�����Ӧ�������Ѿ��ϻ�,������ */
        rtp_read_unlock(&g_rtp_ctrl_tbl[0][tblkey].lock);

        return NF_DROP;
    }
    if (g_rtp_dsp_chan_entry[chn].dir == RTP_DSP_CHAN_DIR_ORIGINAL)
    {
        fw_conn = &g_rtp_ctrl_tbl[0][tblkey].cache->aconn;
    }
    else
    {
        fw_conn = &g_rtp_ctrl_tbl[0][tblkey].cache->bconn;
    }

    /* DSP IPv4 <--> IPv4 Network */
    if (fw_conn->ip_type == PF_INET)
    {
        //ȥ��dspͷ���ռ�
        skb_pull(skb, sizeof(ST_DSP_SOCK_DATA));
	    skb_set_mac_header(skb, -sizeof(struct ethhdr));
        skb_reset_network_header(skb);
        skb_set_transport_header(skb, udphoff);	
        newip = ip_hdr(skb);
        newudp = udp_hdr(skb);
        memmove((__u8*)newudp, (__u8*)udp, sizeof(struct udphdr));
        memmove((__u8*)newip, (__u8*)ip, udphoff);
        
        //���¼���ͷ������
        newip->tot_len = htons(ntohs(newip->tot_len) - sizeof(ST_DSP_SOCK_DATA));
        newudp->len = htons(ntohs(newudp->len) - sizeof(ST_DSP_SOCK_DATA));
        
        //�滻��ַ��Ϣ
        newip->saddr = fw_conn->local_ip.ip;
        if (fw_conn->remote_ip.ip)
        {
            newip->daddr = fw_conn->remote_ip.ip;
        }
        else
        {
            newip->daddr = fw_conn->orig_remote_ip.ip;
        }
        
        /* �޸�dscp */
        #if 1
        newip->tos = ((fw_conn->dscp) << DDOS_DSCP_SHIFT);
        #else
        newip->tos = 0;
        if (fw_conn->dscp)
        {
            rtp_relay_update_dscp_v4(newip, fw_conn->dscp);
        }
        #endif
        newip->frag_off = 0;
        newip->check = 0;

        if (likely(!(fw_conn->flag & KERNEL_ONLY_USE_ORIG_FOR_SEND)) && fw_conn->remote_port)
        {
            newudp->dest = fw_conn->remote_port;
        }
        else
        {
            newudp->dest = fw_conn->orig_remote_port;
        }
        newudp->source = fw_conn->local_port;
        newudp->check = 0;

        #if 0
        skb->csum = 0;
        newudp->check = 0;
        skb->ip_summed = 0;
        newip->check = 0;
        #else
        //���¼���У���
        skb->csum = 0;
        skb->csum = skb_checksum(skb, udphoff, skb->len - udphoff, 0);
        newudp->check = csum_tcpudp_magic (newip->saddr, newip->daddr, skb->len - udphoff, IPPROTO_UDP, skb->csum);

        skb->ip_summed = CHECKSUM_NONE;
        if (0 == newudp->check)
        {
	        newudp->check = CSUM_MANGLED_0;
        }
        newip->check = ip_fast_csum((unsigned char *)newip, newip->ihl);
        #endif
        
    	eth = eth_hdr(skb);
    	memcpy(eth->h_source, fw_conn->local_mac, ETH_ALEN);
        memcpy(eth->h_dest, fw_conn->remote_mac, ETH_ALEN);
    	eth->h_proto = htons(ETH_P_IP);
        
        //skb->dev = dev_get_by_name(&init_net, "eth0");
        skb->dev = fw_conn->dev;
    	skb_push(skb, sizeof(struct ethhdr));

        /* ���·�������ͳ�� */
        fw_conn->statis.fromdspkts++;
        fw_conn->statis.fromdspbytes += htons(newip->tot_len);
        fw_conn->statis.fromdsp_rate += htons(newip->tot_len);

        if (fw_conn->vlanid  & VLAN_VID_MASK)
        {
            if (rtp_relay_vlan_insert_tag(skb, tblkey, fw_conn->vlanid) != 0)
            {
                /* ����vlanͷʧ�� */
                fw_conn->statis.sendpkts_err++;
                hook_debug("inset vlan tag fail. drop packet. \n");
                rtp_read_unlock(&g_rtp_ctrl_tbl[0][tblkey].lock);
                return NF_DROP;
            }
        }

        /*����ץ�����ܣ���dsp���͵ı��ĸ���һ�ݸ����ذ�*/
        if(g_rtp_ctrl_tbl[0][tblkey].captrue_flag)
        {
            rtp_read_unlock(&g_rtp_ctrl_tbl[0][tblkey].lock);
            skb_cp = skb_copy(skb, GFP_ATOMIC);
            if(skb_cp)
            {
                rtp_relay_redirect(skb_cp);
            }
            else
            {
                hook_info("port%u send packet copy failed\n", tblkey);
            }
            rtp_read_lock(&g_rtp_ctrl_tbl[0][tblkey].lock);
        }
        rtp_read_unlock(&g_rtp_ctrl_tbl[0][tblkey].lock);
        /* ץ�� */
        capture_match_and_send(skb,ntohs(newudp->source),1,0);
        
        if(unlikely((g_rtp_ctrl_tbl[0][ntohs(newudp->dest)].cache &&
            (newip->daddr == g_rtp_ctrl_tbl[0][ntohs(newudp->dest)].cache->aconn.local_ip.ip ||
                    newip->daddr == g_rtp_ctrl_tbl[0][ntohs(newudp->dest)].cache->bconn.local_ip.ip))))
        {
            skb_pull(skb, sizeof(struct ethhdr));
            rtp_relay_input_hook_v4(hooknum, skb, in, out, okfn);
        }
        else
        {
    	    ret = dev_queue_xmit(skb);
            if (unlikely(ret != NET_XMIT_SUCCESS && ret != NET_XMIT_CN))
            {
                hook_debug("Error: connid %d, dev queue xmit packet fail.\n", tblkey);
                rtp_read_lock(&g_rtp_ctrl_tbl[0][tblkey].lock);
                if (g_rtp_ctrl_tbl[0][tblkey].cache != NULL)
                {
                    if (fw_conn == &g_rtp_ctrl_tbl[0][tblkey].cache->aconn)
                    {
                        fw_conn->statis.sendpkts_err++;
                    }
                    else if (fw_conn == &g_rtp_ctrl_tbl[0][tblkey].cache->bconn)
                    {
                        fw_conn->statis.sendpkts_err++;
                    }
                }
                rtp_read_unlock(&g_rtp_ctrl_tbl[0][tblkey].lock);
            }
        }
        
        return NF_STOLEN;
    }

    /* DSP IPv4 <--> IPv6 Network */
    if (fw_conn->ip_type == PF_INET6)
    {
        /* dsp to IPv6 network */

        //rtp_read_unlock(&g_rtp_ctrl_tbl[tblkey].lock);
        //(void)dev_queue_xmit(skb);
        
        //return NF_STOLEN;
    }
    
    rtp_read_unlock(&g_rtp_ctrl_tbl[0][tblkey].lock);
        
    return NF_ACCEPT;
}


static struct nf_hook_ops rtp_relay_ops[] = {
	{
	    .hook		= rtp_relay_input_hook_v4,
	    .pf		    = PF_INET,
	    .hooknum	= NF_INET_PRE_ROUTING,
	    .priority	= NF_IP_PRI_FIRST + 20,
    },
    {
	    .hook		= rtp_relay_dsp_out_hook_v4,
	    .pf		    = PF_INET,
	    .hooknum	= NF_INET_LOCAL_OUT,
	    .priority	= NF_IP_PRI_FIRST + 20,
    },
    /**
    {
	    .hook		= rtp_relay_input_hook_v6,
	    .pf		    = PF_INET6,
	    .hooknum	= NF_INET_PRE_ROUTING,
	    .priority	= NF_IP_PRI_FIRST + 20,
    },
    {
		.hook		= rtp_relay_ebt_vlan_in_hook,
		.owner		= THIS_MODULE,
		.pf		    = NFPROTO_BRIDGE,
		.hooknum	= NF_BR_PRE_ROUTING,
		.priority	= NF_BR_PRI_FIRST,
	},
    **/
	{}
};


/* begin timer process code */
/* ֻ����rtp����,     ��ͨudp/tcp������ */
static void rtp_timer_rate_handler(unsigned long data)
{
    int i;
    struct rtp_relay_cache *cache;

    for (i = g_rtp_port_min; i < g_rtp_port_max; i++)
    {
        rtp_read_lock(&g_rtp_ctrl_tbl[0][i].lock);
        if (g_rtp_ctrl_tbl[0][i].cache != NULL)
        {
            cache = g_rtp_ctrl_tbl[0][i].cache;
            if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
        {
            /* calculate aconn rtp flow rate */
            cache->aconn.statis.recvrate_rtime = (cache->aconn.statis.recvrate / g_rtp_rate_timeval);
            cache->aconn.statis.recvrate = 0;
            if (cache->aconn.chan_id != -1)
            {
                cache->aconn.statis.fromdsp_rate_rtime = (cache->aconn.statis.fromdsp_rate / g_rtp_rate_timeval);
                cache->aconn.statis.fromdsp_rate = 0;
            }

            /* calculate bconn rtp flow rate */
            cache->bconn.statis.recvrate_rtime = (cache->bconn.statis.recvrate / g_rtp_rate_timeval);
            cache->bconn.statis.recvrate = 0;
            if (cache->bconn.chan_id != -1)
            {
                cache->bconn.statis.fromdsp_rate_rtime = (cache->bconn.statis.fromdsp_rate / g_rtp_rate_timeval);
                cache->bconn.statis.fromdsp_rate = 0;
            }
            
            /* ת�������쳣���,����һ���÷�ֵʱ֪ͨ�������ȫ������� */
            if (cache->aconn.statis.recvrate_rtime >= g_rtp_flow_max_rate)
            {
                /* ��ȫģ�鱨�� */
                rtp_netlink_send_ddos_report(&cache->aconn);
            }
            if (cache->bconn.statis.recvrate_rtime >= g_rtp_flow_max_rate)
            {
                /* ��ȫģ�鱨�� */
                rtp_netlink_send_ddos_report(&cache->bconn);
            }
        }
        }
        rtp_read_unlock(&g_rtp_ctrl_tbl[0][i].lock);
        
    }

    g_rtp_rate_ticktimer.expires = jiffies + (g_rtp_rate_timeval * g_rtp_hz_ticks);
    add_timer(&g_rtp_rate_ticktimer);

    return;
}

/* ��ʱ����ʼ */
static void rtp_timer_init(void)
{
    hook_info("rtp rate timer init. \n");
    
    init_timer(&g_rtp_rate_ticktimer);
    g_rtp_rate_ticktimer.data = 0;
    g_rtp_rate_ticktimer.expires = jiffies + (g_rtp_rate_timeval * g_rtp_hz_ticks);
    g_rtp_rate_ticktimer.function = rtp_timer_rate_handler;
    add_timer(&g_rtp_rate_ticktimer);

    return;
}

/* ���ٶ�ʱ�� */
static void rtp_timer_fini(void)
{
    del_timer(&g_rtp_rate_ticktimer);
}
/* end   timer process code */

/* begin porc file process code */
static int rtp_proc_entry_read(struct seq_file *m, void *v)
{
    int i;
    unsigned int rtp_cache_cnt = 0;
    struct rtp_relay_cache *cache;

    seq_printf(m, "index ip:port - ip:port/ip:port Code/Psize/SRTP RX:Pkts/Bytes/Rate/ErrPkts/ErrBytes TX:ErrPkts Lock/State/Pkts Chan LRFC/RRFC/DSCP/VLAN/PQOS\n");
    seq_printf(m, "      ip:port - ip:port/ip:port Code/Psize/SRTP RX:Pkts/Bytes/Rate/ErrPkts/ErrBytes TX:ErrPkts Lock/State/Pkts Chan LRFC/RRFC/DSCP/VLAN/PQOS\n");
    //for (i = 0; i < RTP_TBL_SIZE; i++)
    for (i = g_rtp_port_min; i < g_rtp_port_max; i++)
    {
        rtp_read_lock(&g_rtp_ctrl_tbl[0][i].lock);
        if (g_rtp_ctrl_tbl[0][i].cache != NULL)
        {
            cache = g_rtp_ctrl_tbl[0][i].cache;
            if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
        {
            if ((cache->aconn.statis.recvrate != 0) || (cache->bconn.statis.recvrate != 0))
            {
                if (cache->aconn.ip_type == PF_INET)
                {
                    seq_printf(m, "%05d %d.%d.%d.%d:%d - %d.%d.%d.%d:%d/%d.%d.%d.%d:%d %s/%u/%u %u/%u/%u/%u/%u %u %d/%d/%d %d %u/%u/%u/%u/%d\n",
                        i, 
                        NIPQUAD(cache->aconn.local_ip.ip), htons(cache->aconn.local_port),
                        NIPQUAD(cache->aconn.remote_ip.ip), htons(cache->aconn.remote_port),
                        NIPQUAD(cache->aconn.orig_remote_ip.ip), htons(cache->aconn.orig_remote_port), 
                        cache->aconn.media_data.rtp.encode_name, cache->aconn.media_data.rtp.max_psize, 
                        cache->aconn.media_data.rtp.srtp, 
                        cache->aconn.statis.recvpkts, cache->aconn.statis.recvbytes, cache->aconn.statis.recvrate_rtime,
                        cache->aconn.statis.recvpkts_err, cache->aconn.statis.recvbytes_err, 
                        cache->aconn.statis.sendpkts_err, 
                        cache->aconn.media_lock, cache->aconn.media_lock_status_ptks, cache->aconn.media_lock_param, 
                        cache->aconn.chan_id, 
                        cache->aconn.media_data.rtp.rfc2833, cache->aconn.media_data.rtp.rfc2833_remote, 
                        cache->aconn.dscp, cache->aconn.vlanid, cache->aconn.qos_pkts.pkts_power);
                }
                
                if (cache->bconn.ip_type == PF_INET)
                {
                    seq_printf(m, "      %d.%d.%d.%d:%d - %d.%d.%d.%d:%d/%d.%d.%d.%d:%d %s/%u/%u %u/%u/%u/%u/%u %u %d/%d/%d %d %u/%u/%u/%u/%d\n",
                        NIPQUAD(cache->bconn.local_ip.ip), htons(cache->bconn.local_port),
                        NIPQUAD(cache->bconn.remote_ip.ip), htons(cache->bconn.remote_port),
                        NIPQUAD(cache->bconn.orig_remote_ip.ip), htons(cache->bconn.orig_remote_port), 
                        cache->bconn.media_data.rtp.encode_name,  cache->bconn.media_data.rtp.max_psize, 
                        cache->bconn.media_data.rtp.srtp, 
                        cache->bconn.statis.recvpkts, cache->bconn.statis.recvbytes, cache->bconn.statis.recvrate_rtime,
                        cache->bconn.statis.recvpkts_err, cache->bconn.statis.recvbytes_err, 
                        cache->bconn.statis.sendpkts_err, 
                        cache->bconn.media_lock, cache->bconn.media_lock_status_ptks, cache->bconn.media_lock_param, 
                        cache->bconn.chan_id, 
                        cache->bconn.media_data.rtp.rfc2833, cache->bconn.media_data.rtp.rfc2833_remote, 
                        cache->bconn.dscp, cache->bconn.vlanid, cache->bconn.qos_pkts.pkts_power);
                }
                if ((i & 0x1) == 0)
                {
                    rtp_cache_cnt++;
                }
            }
        }
        }
        rtp_read_unlock(&g_rtp_ctrl_tbl[0][i].lock);
    }
    seq_printf(m, "xrtp relay cache count %d.\n", rtp_cache_cnt);

    return 0;
}

static int rtp_proc_entry_read_item(struct seq_file *m, void *v)
{
    int i;
    unsigned int rtp_cache_cnt = 0;
    unsigned int rtp_cache_dsp_cnt = 0;
    struct rtp_relay_cache *cache;
    //unsigned char lip_buff[64] = {0};
    //unsigned char rip_buff[64] = {0};

    seq_printf(m, "RTP Relay Version: 1.x.0.32 for dtls.\n");

    seq_printf(m, "index ip:port[mac] - ip:port[mac/mac] DSP[InPkts/InBytes/PktsOut/BytesOut/OutRate] RTCP[SPkts/LFract/LostPkts/Jitter]\n");
    seq_printf(m, "      ip:port[mac] - ip:port[mac/mac] DSP[InPkts/InBytes/PktsOut/BytesOut/OutRate] RTCP[SPkts/LFract/LostPkts/Jitter]\n");
    //for (i = 0; i < RTP_TBL_SIZE; i++)
    for (i = g_rtp_port_min; i < g_rtp_port_max; i++)
    {
        rtp_read_lock(&g_rtp_ctrl_tbl[0][i].lock);
        if (g_rtp_ctrl_tbl[0][i].cache != NULL)
        {
            cache = g_rtp_ctrl_tbl[0][i].cache;
            if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
        {
            if (cache->aconn.ip_type == PF_INET)
            {
                seq_printf(m, "%05d %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x] - %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x:%02x] %u/%u/%u/%u/%u %u/%u/%u/%u\n",
                    i, 
                    NIPQUAD(cache->aconn.local_ip.ip), htons(cache->aconn.local_port), NMACQUAD(cache->aconn.local_mac),
                    NIPQUAD(cache->aconn.remote_ip.ip), htons(cache->aconn.remote_port), NMACQUAD(cache->aconn.remote_mac), NMACQUAD(cache->aconn.orig_remote_mac),
                    //cache->aconn.media_data.rtp.encode_name, cache->aconn.media_data.rtp.max_psize, 
                    cache->aconn.statis.todspkts, cache->aconn.statis.todspbytes, 
                    cache->aconn.statis.fromdspkts, cache->aconn.statis.fromdspbytes, cache->aconn.statis.fromdsp_rate_rtime, 
                    //cache->aconn.chan_id, 
                    cache->aconn.statis.rtcp.sender_pkts, cache->aconn.statis.rtcp.fraction_lost, 
                    cache->aconn.statis.rtcp.lost_pkts, cache->aconn.statis.rtcp.jitter);
            }
            
            if (cache->bconn.ip_type == PF_INET)
            {
                seq_printf(m, "      %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x] - %d.%d.%d.%d:%d[%02x:%02x:%02x:%02x:%02x:%02x/%02x:%02x:%02x:%02x:%02x:%02x] %u/%u/%u/%u/%u %u/%u/%u/%u\n",
                    NIPQUAD(cache->bconn.local_ip.ip), htons(cache->bconn.local_port), NMACQUAD(cache->bconn.local_mac),
                    NIPQUAD(cache->bconn.remote_ip.ip), htons(cache->bconn.remote_port), NMACQUAD(cache->bconn.remote_mac), NMACQUAD(cache->bconn.orig_remote_mac),
                    //cache->bconn.media_data.rtp.encode_name, cache->bconn.media_data.rtp.max_psize, 
                    cache->bconn.statis.todspkts, cache->bconn.statis.todspbytes, 
                    cache->bconn.statis.fromdspkts, cache->bconn.statis.fromdspbytes, cache->bconn.statis.fromdsp_rate_rtime, 
                    //cache->bconn.chan_id, 
                    cache->bconn.statis.rtcp.sender_pkts, cache->bconn.statis.rtcp.fraction_lost, 
                    cache->bconn.statis.rtcp.lost_pkts, cache->bconn.statis.rtcp.jitter);
            }
            if ((i & 0x1) == 0)
            {
                rtp_cache_cnt++;
                if (cache->aconn.chan_id >= 0)
                {
                    rtp_cache_dsp_cnt++;
                }
            }
        }
        }
        rtp_read_unlock(&g_rtp_ctrl_tbl[0][i].lock);
    }
    seq_printf(m, "xrtp relay cache count %d, transcode:%d\n", rtp_cache_cnt, rtp_cache_dsp_cnt);

    seq_printf(m, "ChanID <--> ConnID.\n");
    rtp_cache_cnt = 0;
    for (i = 0; i < RTP_DSP_CHAN_MAX; i++)
    {
        if (g_rtp_dsp_chan_entry[i].connid)
        {
            seq_printf(m, "ChanID:%03d <--> ConnID:%05d.\n", i, g_rtp_dsp_chan_entry[i].connid);
            rtp_cache_cnt++;
        }
    }
    seq_printf(m, "xrtp relay channel entry count %d.\n", rtp_cache_cnt);

    return 0;
}

static int rtp_proc_entry_open(struct inode *inode, struct file *file)
{
    return single_open(file, rtp_proc_entry_read, NULL);
}

static int rtp_proc_entry_open_item(struct inode *inode, struct file *file)
{
    return single_open(file, rtp_proc_entry_read_item, NULL);
}

static const struct file_operations rtp_proc_entry_fops = {
        .open = rtp_proc_entry_open,
        .read = seq_read,
        .llseek = default_llseek,
};

static const struct file_operations rtp_proc_entry_fops_item = {
        .open = rtp_proc_entry_open_item,
        .read = seq_read,
        .llseek = default_llseek,
};

#ifdef RTP_JITTER_BUFFER
static int rtp_proc_jitter_buffer_read(struct seq_file *m, void *v)
{
    int i, k;
    unsigned int in1, out1, used1, max1, overflow1;
    unsigned int in2, out2, used2, max2, overflow2;
    
    seq_printf(m, "index input output <cache/max> overflow - index input output <cache/max> overflow \n");
    
    for (i = 0; i < RTP_DSP_CHAN_MAX/2; i++)
    {
        in1 = in2 = out1 = out2 = used1 = used2 = 0;
        max1 = max2 = overflow1 = overflow2 = 0;
        spin_lock_bh(&g_jitter_buffer_ctrl[i].lock);
        if (g_jitter_buffer_ctrl[i].input_cnt || g_jitter_buffer_ctrl[i].output_cnt)
        {
            in1  = g_jitter_buffer_ctrl[i].input_cnt;
            out1 = g_jitter_buffer_ctrl[i].output_cnt;
            used1 = g_jitter_buffer_ctrl[i].used_cnt;
            max1 =  g_jitter_buffer_ctrl[i].used_max;
            overflow1 = g_jitter_buffer_ctrl[i].overflow;
        }
        spin_unlock_bh(&g_jitter_buffer_ctrl[i].lock);

        k = i + RTP_DSP_CHAN_MAX/2;
        spin_lock_bh(&g_jitter_buffer_ctrl[k].lock);
        if (g_jitter_buffer_ctrl[k].input_cnt || g_jitter_buffer_ctrl[k].output_cnt)
        {
            in2  = g_jitter_buffer_ctrl[k].input_cnt;
            out2 = g_jitter_buffer_ctrl[k].output_cnt;
            used2 = g_jitter_buffer_ctrl[k].used_cnt;
            max2 =  g_jitter_buffer_ctrl[k].used_max;
            overflow2 = g_jitter_buffer_ctrl[k].overflow;
        }
        spin_unlock_bh(&g_jitter_buffer_ctrl[k].lock);

        if (in1 || in2)
        {
            seq_printf(m, "%03d %8u %8u <%u/%u> %u - %03d %8u %8u <%u/%u> %u \n", 
                        i, in1, out1, used1, max1, overflow1, 
                        k, in2, out2, used2, max2, overflow2);
        }
        
    }

    return 0;
}

static int rtp_proc_jitter_buffer_open(struct inode *inode, struct file *file)
{
    return single_open(file, rtp_proc_jitter_buffer_read, NULL);
}

static const struct file_operations rtp_proc_jitter_buffer_fops = {
        .open = rtp_proc_jitter_buffer_open,
        .read = seq_read,
        .llseek = default_llseek,
};
#endif

#ifdef RTP_PACKET_TIME_DELAY
static int rtp_proc_delay_read(struct seq_file *m, void *v)
{
    int i;
    struct rtp_relay_cache *cache;

    if (g_rtp_delay_pkt_enable)
    {
        seq_printf(m, "index ip:port - ip:port delay[min/max/pkts avg pktin min/max/pkts avg total]\n");
        seq_printf(m, "      ip:port - ip:port delay[min/max/pkts avg pktin min/max/pkts avg total]\n");

        for (i = g_rtp_port_min; i < g_rtp_port_max; i += 2)
        {
            rtp_read_lock(&g_rtp_ctrl_tbl[0][i].lock);
            if (g_rtp_ctrl_tbl[0][i].cache != NULL)
            {
                cache = g_rtp_ctrl_tbl[0][i].cache;
                if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
            {
                if (cache->aconn.delay_min != g_rtp_hz_ticks)
                {
                    if (cache->aconn.ip_type == PF_INET)
                    {
                        seq_printf(m, "%05d %d.%d.%d.%d:%d - %d.%d.%d.%d:%d %u/%u/%u/%u %uus %u/%u/%u %uus %u\n",
                            i, 
                            NIPQUAD(cache->aconn.local_ip.ip), htons(cache->aconn.local_port), 
                            NIPQUAD(cache->aconn.remote_ip.ip), htons(cache->aconn.remote_port), 
                            cache->aconn.delay_min, cache->aconn.delay_max, 
                            cache->aconn.delay_2ms_pkts, cache->aconn.delay_8ms_pkts, 
                            (cache->aconn.delay_total*1000)/(cache->aconn.statis.recvpkts-1),
                            cache->aconn.delay_pktin_min, cache->aconn.delay_pktin_max, cache->aconn.delay_pktin, 
                            ((cache->aconn.delay_pktin_total*1000)/(cache->aconn.statis.recvpkts-1)),
                            cache->aconn.statis.recvpkts);
                    }
                    
                    if (cache->bconn.ip_type == PF_INET)
                    {
                        seq_printf(m, "      %d.%d.%d.%d:%d - %d.%d.%d.%d:%d %u/%u/%u/%u %uus %u/%u/%u %uus %u\n",
                            NIPQUAD(cache->bconn.local_ip.ip), htons(cache->bconn.local_port), 
                            NIPQUAD(cache->bconn.remote_ip.ip), htons(cache->bconn.remote_port), 
                            cache->bconn.delay_min, cache->bconn.delay_max, 
                            cache->bconn.delay_2ms_pkts, cache->bconn.delay_8ms_pkts,
                            (cache->bconn.delay_total*1000)/(cache->bconn.statis.recvpkts - 1),
                            cache->bconn.delay_pktin_min, cache->bconn.delay_pktin_max, cache->bconn.delay_pktin,
                            (cache->bconn.delay_pktin_total*1000)/(cache->bconn.statis.recvpkts-1),
                            cache->bconn.statis.recvpkts);
                    }
                }
            }
            }
            rtp_read_unlock(&g_rtp_ctrl_tbl[0][i].lock);
        }
    }
    else
    {
        seq_printf(m, "index ip:port - ip:port delay[min/max/pkts avg total]\n");
        seq_printf(m, "      ip:port - ip:port delay[min/max/pkts avg total]\n");

        for (i = g_rtp_port_min; i < g_rtp_port_max; i += 2)
        {
            rtp_read_lock(&g_rtp_ctrl_tbl[0][i].lock);
            if (g_rtp_ctrl_tbl[0][i].cache != NULL)
            {
                cache = g_rtp_ctrl_tbl[0][i].cache;
                if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
            {
                if (cache->aconn.delay_min != g_rtp_hz_ticks)
                {
                    if (cache->aconn.ip_type == PF_INET)
                    {
                        seq_printf(m, "%05d %d.%d.%d.%d:%d - %d.%d.%d.%d:%d %u/%u/%u/%u %uus %u\n",
                            i, 
                            NIPQUAD(cache->aconn.local_ip.ip), htons(cache->aconn.local_port), 
                            NIPQUAD(cache->aconn.remote_ip.ip), htons(cache->aconn.remote_port), 
                            cache->aconn.delay_min, cache->aconn.delay_max, 
                            cache->aconn.delay_2ms_pkts, cache->aconn.delay_8ms_pkts, 
                            (cache->aconn.delay_total*1000)/(cache->aconn.statis.recvpkts-1),
                           
                            cache->aconn.statis.recvpkts);
                    }
                    
                    if (cache->bconn.ip_type == PF_INET)
                    {
                        seq_printf(m, "      %d.%d.%d.%d:%d - %d.%d.%d.%d:%d %u/%u/%u/%u %uus %u\n",
                            NIPQUAD(cache->bconn.local_ip.ip), htons(cache->bconn.local_port), 
                            NIPQUAD(cache->bconn.remote_ip.ip), htons(cache->bconn.remote_port), 
                            cache->bconn.delay_min, cache->bconn.delay_max, 
                            cache->bconn.delay_2ms_pkts, cache->bconn.delay_8ms_pkts, 
                            (cache->bconn.delay_total*1000)/(cache->bconn.statis.recvpkts - 1),
                           
                            cache->bconn.statis.recvpkts);
                    }
                }
            }
            }
            rtp_read_unlock(&g_rtp_ctrl_tbl[0][i].lock);
        }
    }   

    return 0;
}

static int rtp_proc_delay_open(struct inode *inode, struct file *file)
{
    return single_open(file, rtp_proc_delay_read, NULL);
}

static const struct file_operations rtp_proc_delay_fops = {
        .open = rtp_proc_delay_open,
        .read = seq_read,
        .llseek = default_llseek,
};
#endif

static int rtp_proc_capture_open(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t rtp_proc_capture_start_write(struct file *filp, const char __user *buf, size_t count, loff_t *off)
{
	char c[128];
	int rc;
    struct rtp_capture_media rtp_capture;

    memset(c, 0, sizeof(c));
	rc = copy_from_user(c, buf, sizeof(c) > count ? count : sizeof(c));
	if (rc)
		return rc;

    memset(&rtp_capture, 0, sizeof(rtp_capture));
    rtp_capture.port = simple_strtoul(c, NULL, 10);
    
    rtp_capture_add(&rtp_capture);

    return count;
}

static const struct file_operations rtp_proc_capture_start_fops = {
    .open = rtp_proc_capture_open,
    .write = rtp_proc_capture_start_write,
};

static ssize_t rtp_proc_capture_stop_write(struct file *filp, const char __user *buf, size_t count, loff_t *off)
{
	char c[128];
	int rc;
    struct rtp_capture_media rtp_capture;

    memset(c, 0, sizeof(c));
	rc = copy_from_user(c, buf, sizeof(c) > count ? count : sizeof(c));
	if (rc)
		return rc;

    memset(&rtp_capture, 0, sizeof(rtp_capture));
    rtp_capture.port = simple_strtoul(c, NULL, 10);
    
    rtp_capture_del(&rtp_capture);

    return count;
}

static const struct file_operations rtp_proc_capture_stop_fops = {
    .open = rtp_proc_capture_open,
    .write = rtp_proc_capture_stop_write,
};

static int rtp_version_read(struct seq_file *m, void *v)
{
    seq_printf(m, "version %s\n", RTP_DRIVER_VERSION);
    return 0;
}

static int rtp_version_open(struct inode *inode, struct file *file)
{
    return single_open(file, rtp_version_read, NULL);
}

static const struct file_operations rtp_version_fops = {
    .open = rtp_version_open,
    .read = seq_read,
    .llseek = default_llseek,
};

static int rtp_proc_entry_init(void)
{
    hook_info("rtp proc file init. \n");
    
    proc_create("xrtp_relay_cache_item", 0644, init_net.proc_net, &rtp_proc_entry_fops_item);
    proc_create("xrtp_relay_cache", 0644, init_net.proc_net, &rtp_proc_entry_fops);
    #ifdef RTP_JITTER_BUFFER
    proc_create("xrtp_jitter_buffer_queue", 0644, init_net.proc_net, &rtp_proc_jitter_buffer_fops);
    #endif
    #ifdef RTP_PACKET_TIME_DELAY
    proc_create("xrtp_relay_delay", 0644, init_net.proc_net, &rtp_proc_delay_fops);
    #endif
    proc_create("xrtp_relay_capture_start", 0755, init_net.proc_net, &rtp_proc_capture_start_fops);
    proc_create("xrtp_relay_capture_stop", 0755, init_net.proc_net, &rtp_proc_capture_stop_fops);
    proc_create("xrtp_version", 0644, init_net.proc_net, &rtp_version_fops);
    
    return 0;
}

static void rtp_proc_entry_fini(void)
{
    remove_proc_entry("xrtp_relay_cache_item", init_net.proc_net);
    remove_proc_entry("xrtp_relay_cache", init_net.proc_net);
    #ifdef RTP_JITTER_BUFFER
    remove_proc_entry("xrtp_jitter_buffer_queue", init_net.proc_net);
    #endif
    #ifdef RTP_PACKET_TIME_DELAY
    remove_proc_entry("xrtp_relay_delay", init_net.proc_net);
    #endif
    remove_proc_entry("xrtp_relay_capture_start", init_net.proc_net);
    remove_proc_entry("xrtp_relay_capture_stop", init_net.proc_net);

    return;
}
/* end   porc file process code */


/* begin sysctl process code */
static ctl_table rtp_sysctl_table[] = {
	{
		.procname	= "xrtp_relay_port_min",            /* table 0 */
		.data		= &g_rtp_port_min,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_relay_port_max",
		.data		= &g_rtp_port_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_relay_debug_enable",        /* table 2 */
		.data		= &g_debug_enable,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_relay_conn_count",
		.data		= &g_rtp_atomic_conns_count.counter,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_relay_timeval_rate", 
		.data		= &g_rtp_rate_timeval,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_relay_media_lock_pkts",     /* table 5 */
		.data		= &g_rtp_media_lock_pkts,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_flow_ddos_max_rate",
		.data		= &g_rtp_flow_max_rate,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_check_enable",              /* table 7 */
		.data		= &g_rtp_check_enable,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_jitter_buffer_ticks",
		.data		= &g_jitter_buffer_ticks,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_jitter_buffer_enable",
		.data		= &g_jitter_buffer_enable,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_jitter_buffer_size",        /* table 10 */
		.data		= &g_jitter_buffer_size,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_jitter_buffer_max",
		.data		= &g_jitter_buffer_max,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_jitter_buffer_times_ms",    /* table 12 */
		.data		= &g_jigger_buffer_times_ms,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_qos_pkts_power",            /* table 13 */
		.data		= &g_rtp_qos_pkts_power,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_hz_ticks",                  /* table 14 */
		.data		= &g_rtp_hz_ticks,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "xrtp_qos_audio_pkts_count",            /* table 15 */
		.data		= &g_rtp_qos_audio_pkts_count,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
    {
        .procname   = "xrtp_qos_image_pkts_count",            /* table 16 */
        .data       = &g_rtp_qos_image_pkts_count,
        .maxlen     = sizeof(unsigned int),
        .mode       = 0644,
        .proc_handler   = proc_dointvec,
    },
	{ }
};

static struct ctl_path rtp_sysctl_path[] = {
	{ .procname = "net", },
	{ .procname = "xflow", },
	{ }
};

static int rtp_sysctl_init(struct net *net)
{
	struct ctl_table *table;

	table = kmemdup(rtp_sysctl_table, sizeof(rtp_sysctl_table),
			GFP_KERNEL);
	if (!table)
		goto out_kmemdup;

	table[0].data = &g_rtp_port_min;
	table[1].data = &g_rtp_port_max;
	table[2].data = &g_debug_enable;
    table[3].data = &g_rtp_atomic_conns_count.counter;
    table[4].data = &g_rtp_rate_timeval;
    table[5].data = &g_rtp_media_lock_pkts;
    table[6].data = &g_rtp_flow_max_rate;
    table[7].data = &g_rtp_check_enable;
    table[8].data = &g_jitter_buffer_ticks;
    table[9].data = &g_jitter_buffer_enable;
    table[10].data = &g_jitter_buffer_size;
    table[11].data = &g_jitter_buffer_max;
    table[12].data = &g_jigger_buffer_times_ms;
    table[13].data = &g_rtp_qos_pkts_power;
    table[14].data = &g_rtp_hz_ticks;
    table[15].data = &g_rtp_qos_audio_pkts_count;
    table[16].data = &g_rtp_qos_image_pkts_count;

	g_rtp_sysctl_header = register_net_sysctl_table(net, rtp_sysctl_path, table);
	if (!g_rtp_sysctl_header)
	{
		goto out_unregister_xflow;
	}

	return 0;

out_unregister_xflow:
    
	kfree(table);
out_kmemdup:
    
	return -ENOMEM;
}

static void rtp_sysctl_fini(struct net *net)
{
	struct ctl_table *table;

    if (g_rtp_sysctl_header)
    {
    	table = g_rtp_sysctl_header->ctl_table_arg;
    	unregister_net_sysctl_table(g_rtp_sysctl_header);
    	kfree(table);
        g_rtp_sysctl_header = NULL;
    }

    return;
}
/* end   sysctl process code */


/* begin ioctl process code */
static struct cdev rtp_cdev;
static dev_t rtp_dev_no;
static struct class *rtp_dev_class = NULL;
static struct device *rtp_device = NULL;

static int  rtp_ioctl_open(struct inode *inode, struct file *filp)
{
	return 0;
}

static int  rtp_ioctl_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static long rtp_ioctl_cmd(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct rtp_relay_cache *cache;
    struct rm_media_statis stats;
    int result = -1;
    __u16 connid;

    if (copy_from_user(&stats, (struct rm_media_statis *)arg, sizeof(struct rm_media_statis)))
    {
        return -1;
    }

    //hook_debug("ioctl get connID(%d) info.\r\n", stats.conn_id);

    connid = (__u16)stats.conn_id;

    if ((connid & 0x1) || (connid >= 65535))
    {
        hook_debug("ioctl get connID(%d) invalid.\r\n", stats.conn_id);
        return -2;
    }

    switch (cmd) 
    {
        case RTP_IOC_READ_STATIS:
            memset(&stats, 0, sizeof(stats));
            rtp_read_lock(&g_rtp_ctrl_tbl[0][connid].lock);
            cache = g_rtp_ctrl_tbl[0][connid].cache;
            if (cache != NULL)
            {
                if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
                {
                stats.astat.recvpkts = cache->aconn.statis.recvpkts;
                stats.astat.recvbytes = cache->aconn.statis.recvbytes;
                stats.astat.recvrate = cache->aconn.statis.recvrate_rtime;
                stats.astat.recvpkts_err = cache->aconn.statis.recvpkts_err;
                stats.astat.recvbytes_err = cache->aconn.statis.recvbytes_err;
                if (cache->aconn.chan_id != -1)
                {
                    stats.astat.sendpkts = cache->aconn.statis.fromdspkts;
                    stats.astat.sendbytes = cache->aconn.statis.fromdspbytes;
                    stats.astat.sendrate = cache->aconn.statis.fromdsp_rate_rtime;
                }
                else
                {
                    stats.astat.sendpkts = cache->bconn.statis.recvpkts;
                    stats.astat.sendbytes = cache->bconn.statis.recvbytes;
                    stats.astat.sendrate = cache->bconn.statis.recvrate_rtime;
                }
                
                stats.bstat.recvpkts = cache->bconn.statis.recvpkts;
                stats.bstat.recvbytes = cache->bconn.statis.recvbytes;
                stats.bstat.recvrate = cache->bconn.statis.recvrate_rtime;
                stats.bstat.recvpkts_err = cache->bconn.statis.recvpkts_err;
                stats.bstat.recvbytes_err = cache->bconn.statis.recvbytes_err;
                if (cache->bconn.chan_id != -1)
                {
                    stats.bstat.sendpkts = cache->bconn.statis.fromdspkts;
                    stats.bstat.sendbytes = cache->bconn.statis.fromdspbytes;
                    stats.bstat.sendrate = cache->bconn.statis.fromdsp_rate_rtime;
                }
                else
                {
                    stats.bstat.sendpkts = cache->aconn.statis.recvpkts;
                    stats.bstat.sendbytes = cache->aconn.statis.recvbytes;
                    stats.bstat.sendrate = cache->aconn.statis.recvrate_rtime;
                }
                }

                result = 0;
            }
            rtp_read_unlock(&g_rtp_ctrl_tbl[0][connid].lock);

            connid++;
            rtp_read_lock(&g_rtp_ctrl_tbl[0][connid].lock);
            cache = g_rtp_ctrl_tbl[0][connid].cache;
            if (cache != NULL)
            {
                if(cache->aconn.media_type != RM_MEDIA_APPLICATION)
                {
                stats.astat.rtcp.fraction_lost = cache->aconn.statis.rtcp.fraction_lost;
                stats.astat.rtcp.jitter = cache->aconn.statis.rtcp.jitter;
                stats.astat.rtcp.lost_pkts = cache->aconn.statis.rtcp.lost_pkts;
                stats.astat.rtcp.sender_pkts = cache->aconn.statis.rtcp.sender_pkts;
                
                stats.bstat.rtcp.fraction_lost = cache->bconn.statis.rtcp.fraction_lost;
                stats.bstat.rtcp.jitter = cache->bconn.statis.rtcp.jitter;
                stats.bstat.rtcp.lost_pkts = cache->bconn.statis.rtcp.lost_pkts;
                stats.bstat.rtcp.sender_pkts = cache->bconn.statis.rtcp.sender_pkts;
            }
            }
            rtp_read_unlock(&g_rtp_ctrl_tbl[0][connid].lock);

            copy_to_user((void *)arg, (void *)&stats, sizeof(stats));
            
            break;

        default:
            hook_info("ERROR: IOCTL CMD ERROR.\r\n");
            
            break;
    }

    if (g_debug_enable == 9)
    {
        hook_info("ioctrl connID(%d) aconn rx:%u/%u/%u tx:%u/%u/%u, rtcp:%u/%u/%u/%u \n", --connid, 
                    stats.astat.recvpkts, stats.astat.recvbytes, stats.astat.recvrate, 
                    stats.astat.sendpkts, stats.astat.sendbytes, stats.astat.sendrate, 
                    stats.astat.rtcp.fraction_lost, stats.astat.rtcp.jitter, 
                    stats.astat.rtcp.lost_pkts, stats.astat.rtcp.sender_pkts);

        hook_info("ioctrl connID(%d) bconn rx:%u/%u/%u tx:%u/%u/%u, rtcp:%u/%u/%u%u \n", connid, 
                    stats.bstat.recvpkts, stats.bstat.recvbytes, stats.bstat.recvrate, 
                    stats.bstat.sendpkts, stats.bstat.sendbytes, stats.bstat.sendrate,
                    stats.bstat.rtcp.fraction_lost, stats.bstat.rtcp.jitter, 
                    stats.bstat.rtcp.lost_pkts, stats.bstat.rtcp.sender_pkts);
    }
    
    return result;
}

static const struct file_operations rtp_ioctl_fops = {
        .open = rtp_ioctl_open,
        .release = rtp_ioctl_close,
        .unlocked_ioctl = rtp_ioctl_cmd,
};

static void rtp_ioctl_init(void)
{
    int res;

    hook_info("xrtp relay module init ioctl cdev.\r\n");
    
    /* ��ȡ�ַ��豸�� */
    res = alloc_chrdev_region(&rtp_dev_no, 0, 1, "rtp_relay");
    if (res < 0)
    {
        hook_info("ERROR: Alloc Cdev Fail.\r\n");
        return;
    }

    cdev_init(&rtp_cdev, &rtp_ioctl_fops);
    rtp_cdev.owner = THIS_MODULE;
    rtp_cdev.ops = &rtp_ioctl_fops;

    /* ע���豸 */
    res = cdev_add(&rtp_cdev, rtp_dev_no, 1);
    if (res)
    {
        hook_info("ERROR: Register Cdev Fail.\r\n");
        return;
    }

    /* �����ڵ� */
    rtp_dev_class = class_create(THIS_MODULE, "rtp_relay");
	res = PTR_ERR(rtp_dev_class);
	if (IS_ERR(rtp_dev_class))
	{
        hook_info("ERROR: Create Dev Class Fail.\r\n");
		return;
	}
	rtp_device = device_create(rtp_dev_class, NULL, rtp_dev_no, NULL, "rtp_relay");
    if(IS_ERR(rtp_device))
    {
        hook_info("ERROR: Create Device Fail.\r\n");
        return;
    }

    return;
}

static void rtp_ioctl_fini(void)
{
    unregister_chrdev_region(rtp_dev_no, 1);
    cdev_del(&rtp_cdev);

    /* ע�������ڵ� */
    if (rtp_dev_class != NULL)
    {
        if (rtp_device != NULL)
        {
            device_destroy(rtp_dev_class, rtp_dev_no);
            rtp_device = NULL;
        }
        
        class_destroy(rtp_dev_class);
        rtp_dev_class = NULL;
    }

    return;
}
/* end   ioctl process code */

/* begin dsp test mode process */
#ifdef RTP_DSP_TEST_MODE
static void rtp_test_add_entry(void)
{
    struct rm_media_tbl tbl;
    int i;

    memset(&tbl, 0, sizeof(tbl));

#if 0
    tbl.aconn.ip_type = 4;
    tbl.aconn.local_mac[0] = 0x00;
    tbl.aconn.local_mac[1] = 0x11;
    tbl.aconn.local_mac[2] = 0x22;
    tbl.aconn.local_mac[3] = 0x33;
    tbl.aconn.local_mac[4] = 0x01;
    tbl.aconn.local_mac[5] = 0x01;
    tbl.aconn.local_ip.ip = in_aton("10.251.1.1");
    tbl.aconn.remote_mac[0] = 0x00;
    tbl.aconn.remote_mac[1] = 0x11;
    tbl.aconn.remote_mac[2] = 0x22;
    tbl.aconn.remote_mac[3] = 0x33;
    tbl.aconn.remote_mac[4] = 0x01;
    tbl.aconn.remote_mac[5] = 0x02;
    tbl.aconn.remote_ip.ip = in_aton("10.251.1.2");
    /* ���ô��ʱ��20ms */
    tbl.aconn.media_data.rtp.max_ptime = 20;

    tbl.bconn.ip_type = 4;
    tbl.bconn.local_mac[0] = 0x00;
    tbl.bconn.local_mac[1] = 0x11;
    tbl.bconn.local_mac[2] = 0x22;
    tbl.bconn.local_mac[3] = 0x33;
    tbl.bconn.local_mac[4] = 0x01;
    tbl.bconn.local_mac[5] = 0x01;
    tbl.bconn.local_ip.ip = in_aton("10.251.1.1");
    tbl.bconn.remote_mac[0] = 0x00;
    tbl.bconn.remote_mac[1] = 0x11;
    tbl.bconn.remote_mac[2] = 0x22;
    tbl.bconn.remote_mac[3] = 0x33;
    tbl.bconn.remote_mac[4] = 0x01;
    tbl.bconn.remote_mac[5] = 0x02;
    tbl.bconn.remote_ip.ip = in_aton("10.251.1.2");
    /* ���ô��ʱ��20ms */
    tbl.bconn.media_data.rtp.max_ptime = 20;
 
    for (i = 0; i <= 255; i++)
    {
        tbl.conn_id = (8000 + (i*2));
        tbl.aconn.local_port = (8000 + (i*2));
        tbl.aconn.remote_port = (8000 + (i*2));
        tbl.aconn.chan_id = i;
        
        tbl.bconn.local_port = (8000 + (i*2));
        tbl.bconn.remote_port = (8512 + (i*2));
        tbl.bconn.chan_id = (i + 256);

        if (!g_dsp_test_mode)
        {
            tbl.aconn.chan_id = -1;
            tbl.bconn.chan_id = -1;
        }

        rtp_netlink_tbl_create(&tbl, 0);
    }
#elif 0
    /*audio test*/
    /*eth1*/
    tbl.aconn.ip_type = 4;
    tbl.aconn.local_mac[0] = 0xFA;
    tbl.aconn.local_mac[1] = 0x11;
    tbl.aconn.local_mac[2] = 0x23;
    tbl.aconn.local_mac[3] = 0x24;
    tbl.aconn.local_mac[4] = 0x25;
    tbl.aconn.local_mac[5] = 0x27;
    tbl.aconn.local_ip.ip = in_aton("192.168.11.1");
    tbl.aconn.remote_mac[0] = 0x00;
    tbl.aconn.remote_mac[1] = 0x0E;
    tbl.aconn.remote_mac[2] = 0x04;
    tbl.aconn.remote_mac[3] = 0x31;
    tbl.aconn.remote_mac[4] = 0x19;
    tbl.aconn.remote_mac[5] = 0x78;
    tbl.aconn.remote_ip.ip = in_aton("192.168.11.3");
    /* ���ô��ʱ��20ms */
    tbl.aconn.media_data.rtp.max_ptime = 20;
    tbl.aconn.media_type = RM_MEDIA_AUDIO;

    tbl.bconn.ip_type = 4;
    tbl.bconn.local_mac[0] = 0xFA;
    tbl.bconn.local_mac[1] = 0x11;
    tbl.bconn.local_mac[2] = 0x23;
    tbl.bconn.local_mac[3] = 0x24;
    tbl.bconn.local_mac[4] = 0x25;
    tbl.bconn.local_mac[5] = 0x27;
    tbl.bconn.local_ip.ip = in_aton("192.168.11.1");
    tbl.bconn.remote_mac[0] = 0x00;
    tbl.bconn.remote_mac[1] = 0x0E;
    tbl.bconn.remote_mac[2] = 0x04;
    tbl.bconn.remote_mac[3] = 0x31;
    tbl.bconn.remote_mac[4] = 0x19;
    tbl.bconn.remote_mac[5] = 0x78;
    tbl.bconn.remote_ip.ip = in_aton("192.168.11.3");
    /* ���ô��ʱ��20ms */
    tbl.bconn.media_data.rtp.max_ptime = 20;
    tbl.bconn.media_type = RM_MEDIA_AUDIO;

    tbl.conn_id = 32768;
    tbl.aconn.local_port = 32768;
    tbl.aconn.remote_port = 32768;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 32768;
    tbl.bconn.remote_port = 8512;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 34816;
    tbl.aconn.local_port = 34816;
    tbl.aconn.remote_port = 34816;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 34816;
    tbl.bconn.remote_port = 8514;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 36864;
    tbl.aconn.local_port = 36864;
    tbl.aconn.remote_port = 36864;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 36864;
    tbl.bconn.remote_port = 8516;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 38912;
    tbl.aconn.local_port = 38912;
    tbl.aconn.remote_port = 38912;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 38912;
    tbl.bconn.remote_port = 8518;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 40960;
    tbl.aconn.local_port = 40960;
    tbl.aconn.remote_port = 40960;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 40960;
    tbl.bconn.remote_port = 8520;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 43008;
    tbl.aconn.local_port = 43008;
    tbl.aconn.remote_port = 43008;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 43008;
    tbl.bconn.remote_port = 8522;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 45056;
    tbl.aconn.local_port = 45056;
    tbl.aconn.remote_port = 45056;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 45056;
    tbl.bconn.remote_port = 8524;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.conn_id = 47104;
    tbl.aconn.local_port = 47104;
    tbl.aconn.remote_port = 47104;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 47104;
    tbl.bconn.remote_port = 8526;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    /*vedio test*/
    /*eth1*/
    tbl.aconn.ip_type = 4;
    tbl.aconn.local_mac[0] = 0xFA;
    tbl.aconn.local_mac[1] = 0x11;
    tbl.aconn.local_mac[2] = 0x23;
    tbl.aconn.local_mac[3] = 0x24;
    tbl.aconn.local_mac[4] = 0x25;
    tbl.aconn.local_mac[5] = 0x27;
    tbl.aconn.local_ip.ip = in_aton("192.168.11.1");
    tbl.aconn.remote_mac[0] = 0x00;
    tbl.aconn.remote_mac[1] = 0x0E;
    tbl.aconn.remote_mac[2] = 0x04;
    tbl.aconn.remote_mac[3] = 0x31;
    tbl.aconn.remote_mac[4] = 0x19;
    tbl.aconn.remote_mac[5] = 0x78;
    tbl.aconn.remote_ip.ip = in_aton("192.168.11.3");
    tbl.aconn.media_type = RM_MEDIA_VIDEO;
    tbl.aconn.media_data.rtp.payload = 103;

    tbl.bconn.ip_type = 4;
    tbl.bconn.local_mac[0] = 0xFA;
    tbl.bconn.local_mac[1] = 0x11;
    tbl.bconn.local_mac[2] = 0x23;
    tbl.bconn.local_mac[3] = 0x24;
    tbl.bconn.local_mac[4] = 0x25;
    tbl.bconn.local_mac[5] = 0x27;
    tbl.bconn.local_ip.ip = in_aton("192.168.11.1");
    tbl.bconn.remote_mac[0] = 0x00;
    tbl.bconn.remote_mac[1] = 0x0E;
    tbl.bconn.remote_mac[2] = 0x04;
    tbl.bconn.remote_mac[3] = 0x31;
    tbl.bconn.remote_mac[4] = 0x19;
    tbl.bconn.remote_mac[5] = 0x78;
    tbl.bconn.remote_ip.ip = in_aton("192.168.11.3");
    tbl.bconn.media_type = RM_MEDIA_VIDEO;
    tbl.bconn.media_data.rtp.payload = 103;
    

    tbl.conn_id = 32770;
    tbl.aconn.local_port = 32770;
    tbl.aconn.remote_port = 32770;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 32770;
    tbl.bconn.remote_port = 8550;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);
#else
    /*audio test*/
    /*eth1*/
    tbl.aconn.ip_type = 4;
    tbl.aconn.local_mac[0] = 0xFA;
    tbl.aconn.local_mac[1] = 0x11;
    tbl.aconn.local_mac[2] = 0x23;
    tbl.aconn.local_mac[3] = 0x24;
    tbl.aconn.local_mac[4] = 0x25;
    tbl.aconn.local_mac[5] = 0x27;
    tbl.aconn.local_ip.ip = in_aton("192.168.11.1");
    tbl.aconn.remote_mac[0] = 0x00;
    tbl.aconn.remote_mac[1] = 0x0E;
    tbl.aconn.remote_mac[2] = 0x04;
    tbl.aconn.remote_mac[3] = 0x31;
    tbl.aconn.remote_mac[4] = 0x19;
    tbl.aconn.remote_mac[5] = 0x78;
    tbl.aconn.remote_ip.ip = in_aton("192.168.11.3");
    /* ���ô��ʱ��20ms */
    tbl.aconn.media_data.rtp.max_ptime = 20;
    tbl.aconn.media_type = RM_MEDIA_AUDIO;

    tbl.bconn.ip_type = 4;
    tbl.bconn.local_mac[0] = 0xFA;
    tbl.bconn.local_mac[1] = 0x11;
    tbl.bconn.local_mac[2] = 0x23;
    tbl.bconn.local_mac[3] = 0x24;
    tbl.bconn.local_mac[4] = 0x25;
    tbl.bconn.local_mac[5] = 0x27;
    tbl.bconn.local_ip.ip = in_aton("192.168.11.1");
    tbl.bconn.remote_mac[0] = 0xFA;
    tbl.bconn.remote_mac[1] = 0x11;
    tbl.bconn.remote_mac[2] = 0x23;
    tbl.bconn.remote_mac[3] = 0x24;
    tbl.bconn.remote_mac[4] = 0x25;
    tbl.bconn.remote_mac[5] = 0x26;
    tbl.bconn.remote_ip.ip = in_aton("192.168.12.1");
    /* ���ô��ʱ��20ms */
    tbl.bconn.media_data.rtp.max_ptime = 20;
    tbl.bconn.media_type = RM_MEDIA_AUDIO;

    tbl.conn_id = 32768;
    tbl.aconn.local_port = 32768;
    tbl.aconn.remote_port = 32768;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 32768;
    tbl.bconn.remote_port = 32770;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);

    tbl.aconn.ip_type = 4;
    tbl.aconn.local_mac[0] = 0xFA;
    tbl.aconn.local_mac[1] = 0x11;
    tbl.aconn.local_mac[2] = 0x23;
    tbl.aconn.local_mac[3] = 0x24;
    tbl.aconn.local_mac[4] = 0x25;
    tbl.aconn.local_mac[5] = 0x26;
    tbl.aconn.local_ip.ip = in_aton("192.168.12.1");
    tbl.aconn.remote_mac[0] = 0xFA;
    tbl.aconn.remote_mac[1] = 0x11;
    tbl.aconn.remote_mac[2] = 0x23;
    tbl.aconn.remote_mac[3] = 0x24;
    tbl.aconn.remote_mac[4] = 0x25;
    tbl.aconn.remote_mac[5] = 0x27;
    tbl.aconn.remote_ip.ip = in_aton("192.168.11.1");
    /* ���ô��ʱ��20ms */
    tbl.aconn.media_data.rtp.max_ptime = 20;
    tbl.aconn.media_type = RM_MEDIA_AUDIO;

    tbl.bconn.ip_type = 4;
    tbl.bconn.local_mac[0] = 0xFA;
    tbl.bconn.local_mac[1] = 0x11;
    tbl.bconn.local_mac[2] = 0x23;
    tbl.bconn.local_mac[3] = 0x24;
    tbl.bconn.local_mac[4] = 0x25;
    tbl.bconn.local_mac[5] = 0x26;
    tbl.bconn.local_ip.ip = in_aton("192.168.12.1");
    tbl.bconn.remote_mac[0] = 0x00;
    tbl.bconn.remote_mac[1] = 0x0E;
    tbl.bconn.remote_mac[2] = 0x04;
    tbl.bconn.remote_mac[3] = 0x31;
    tbl.bconn.remote_mac[4] = 0x19;
    tbl.bconn.remote_mac[5] = 0x78;
    tbl.bconn.remote_ip.ip = in_aton("192.168.12.3");
    /* ���ô��ʱ��20ms */
    tbl.bconn.media_data.rtp.max_ptime = 20;
    tbl.bconn.media_type = RM_MEDIA_AUDIO;

    tbl.conn_id = 32770;
    tbl.aconn.local_port = 32770;
    tbl.aconn.remote_port = 32768;
    tbl.aconn.chan_id = -1;
    tbl.bconn.local_port = 32770;
    tbl.bconn.remote_port = 8514;
    tbl.bconn.chan_id = -1;
    rtp_netlink_tbl_create(&tbl, 0);
#endif

    return;
}
/* end   dsp test mode process */
#endif

static int rtp_vlan_ebt_broute_untag(struct sk_buff *skb)
{
    //unsigned short vlan_tci;
	//unsigned short vlan_id;
    
    if (vlan_tx_tag_present(skb)) {
		//vlan_tci = vlan_tx_tag_get(skb);
        //vlan_id = vlan_tci & VLAN_VID_MASK;

        skb->vlan_tci = 0;
	}

    /**
    if (g_debug_enable == 89)
    {
        if (!skb->tstamp.tv64)
        {
            __net_timestamp(skb);
        }
    }
    **/

    /* bridge it */
    return 0;
}

static int rtp_vlan_ebtable_broute_init(void)
{
	br_should_route_hook_t *rhook;
    
    rhook = rcu_dereference(br_should_route_hook);
    if (rhook)
    {
        hook_info("Warning: ebtable enabled. broute hook replace vlan all untag func. \n");
    }
    else 
    {
        hook_info("register ebtable vlan all untag func. \n");
    }
    
	/* see br_input.c */
	RCU_INIT_POINTER(br_should_route_hook,
			   (br_should_route_hook_t *)rtp_vlan_ebt_broute_untag);
    
	return 0;
}

static void rtp_vlan_ebtable_broute_fini(void)
{
	RCU_INIT_POINTER(br_should_route_hook, NULL);
	synchronize_net();
}

int __init rtp_relay_init(void)
{
    int i;
    unsigned long ticks_start, ticks;

	hook_info("rtp_relay module init, version:%s\n", RTP_DRIVER_VERSION);

    /* g_hz_tickes value init */
    ticks_start = jiffies;
    msleep(10);
    ticks = jiffies - ticks_start;
    if (ticks >= 10)
    {
        g_rtp_hz_ticks = 1000;
    }
    else
    {
        g_rtp_hz_ticks = 100;
    }
    hook_info("rtp_relay module init, HZ:%u. ticks:%lu \n", g_rtp_hz_ticks, ticks);

    #ifdef RTP_DRIVER_PKT_DISPATCH
    /* ע��ַ�udp�˿� */
    rtp_packet_dispatch_register();
    #endif
    
    g_loopback_addr = in_aton("127.0.0.1");
    hook_info("loopback:0x%x -> %d.%d.%d.%d, HZ:%u\r\n", g_loopback_addr, NIPQUAD(g_loopback_addr), g_rtp_hz_ticks);

    atomic_set(&g_rtp_atomic_conns_count, 0);

    /* ����ר�û���� */
    g_rtp_cachep = kmem_cache_create("xrtp_relay_kmem_cache", 
                            sizeof(struct rtp_relay_cache), 0, SLAB_DESTROY_BY_RCU, NULL);
    if (!g_rtp_cachep)
    {
        hook_info("create rtp kmem cache fail.\r\n");
        return -1;
    }

    /* udpת����ĳ�ʼ�� */
    g_rtp_ctrl_tbl[0] = (struct rtp_ctrl_tbl *)kmalloc(sizeof(struct rtp_ctrl_tbl) * RTP_TBL_SIZE, GFP_KERNEL);
    if(!g_rtp_ctrl_tbl[0])
    {
        kmem_cache_destroy(g_rtp_cachep);
        g_rtp_cachep = NULL;
        hook_info("kmalloc rtp forwrad table memory fail.\r\n");
        return -1;     
    }
    
    /* tcpת����ĳ�ʼ�� */
    g_rtp_ctrl_tbl[1] = (struct rtp_ctrl_tbl *)kmalloc(sizeof(struct rtp_ctrl_tbl) * RTP_TBL_SIZE, GFP_KERNEL);
    if (!g_rtp_ctrl_tbl[1] )
    {
        kmem_cache_destroy(g_rtp_cachep);
        g_rtp_cachep = NULL;
        kfree(g_rtp_ctrl_tbl[0]);
        g_rtp_ctrl_tbl[0] = NULL;
        hook_info("kmalloc rtp forwrad table memory fail.\r\n");
        return -1;
    }
    memset(g_rtp_ctrl_tbl[0], 0, sizeof(struct rtp_ctrl_tbl) * RTP_TBL_SIZE);
    memset(g_rtp_ctrl_tbl[1], 0, sizeof(struct rtp_ctrl_tbl) * RTP_TBL_SIZE);    
    
    for (i = 0; i < RTP_TBL_SIZE; i++)
    {
        #ifdef RTP_LOCK_SPINLOCK
        spin_lock_init(&g_rtp_ctrl_tbl[0][i].lock);
        spin_lock_init(&g_rtp_ctrl_tbl[1][i].lock);        
        #else
        rwlock_init(&g_rtp_ctrl_tbl[0][i].lock);
        rwlock_init(&g_rtp_ctrl_tbl[1][i].lock);
        #endif
        g_rtp_ctrl_tbl[0][i].cache = NULL;
        g_rtp_ctrl_tbl[0][i].captrue_flag = 0;
        g_rtp_ctrl_tbl[1][i].cache = NULL;
        g_rtp_ctrl_tbl[1][i].captrue_flag = 0;

    }

    /* netlink��ʼ������ */
	//rtp_nfnl = netlink_kernel_create(&init_net, NETLINK_XRTP_RELAY_MODULE, &rtp_cfg);
	rtp_nfnl = netlink_kernel_create(&init_net, NETLINK_XRTP_RELAY_MODULE, 0, rtp_netlink_rcv, NULL, THIS_MODULE);
	if (!rtp_nfnl)
	{   
        kmem_cache_destroy(g_rtp_cachep);
        g_rtp_cachep = NULL;

        kfree(g_rtp_ctrl_tbl[0]);
        g_rtp_ctrl_tbl[0] = NULL;
        kfree(g_rtp_ctrl_tbl[1]);
        g_rtp_ctrl_tbl[1] = NULL;
        
        hook_info("kernel create netlink socket fail.\r\n");
		return -1;
	}

    /* ��ʼ������ͳ�ƶ�ʱ�� */
    (void)rtp_timer_init();

    (void)rtp_sysctl_init(&init_net);

    rtp_proc_entry_init();

    for (i = 0; i < RTP_DSP_CHAN_MAX; i++)
    {
        g_rtp_dsp_chan_entry[i].connid = 0;
        g_rtp_dsp_chan_entry[i].dir = 0;
    }

    /* iocrlע�� */
    rtp_ioctl_init();

    /* vlan all untag init */
    if (g_rtp_vlan_all_untag)
    {
        rtp_vlan_ebtable_broute_init();
    }

    #ifdef RTP_JITTER_BUFFER
    if (rtp_relay_jitter_buffer_init() != 0)
    {
        hook_info("init rtp relay jitter buffer queue fail. \n");
        g_jitter_buffer_enable = 0;
        if (g_rtp_skb_cache_buffer)
        {
            kfree(g_rtp_skb_cache_buffer);
            g_rtp_skb_cache_buffer = NULL;
        }
    }
    #endif

    /* step last: ע��rtp���Ĵ�����Ӻ��� */
    if (nf_register_hooks(rtp_relay_ops, ARRAY_SIZE(rtp_relay_ops)) < 0)
    {
        hook_info("%s, register xflow statis hook fail.\r\n", __FUNCTION__);
    }

    #ifdef RTP_DSP_TEST_MODE
    g_rtp_check_enable = 0;
    /* only for dsp utest */
    rtp_test_add_entry();
    #endif

    return 0;
}

void __exit rtp_relay_fini(void)
{
    int i;

    /* step first: ע��netfilter������Ӻ��� */
    nf_unregister_hooks(rtp_relay_ops, ARRAY_SIZE(rtp_relay_ops));

    #ifdef RTP_JITTER_BUFFER
    rtp_relay_jitter_buffer_fini();
    #endif

    /* vlan untag fini */
    if (g_rtp_vlan_all_untag)
    {
        rtp_vlan_ebtable_broute_fini();
    }

    /* ioctl ע�� */
    rtp_ioctl_fini();

    hook_debug("xrtp relay module fini.\r\n");
    rtp_proc_entry_fini();

    hook_debug("xrtp relay module fini sysctl.\r\n");
    (void)rtp_sysctl_fini(&init_net);

    /* ���ٶ�ʱ�� */
    (void)rtp_timer_fini();

    if (rtp_nfnl != NULL)
    {
        netlink_kernel_release(rtp_nfnl);
        rtp_nfnl = NULL;
    }

    for (i = 0; i < RTP_DSP_CHAN_MAX; i++)
    {
        g_rtp_dsp_chan_entry[i].connid = 0;
        g_rtp_dsp_chan_entry[i].dir = 0;
    }

    /* �ͷ�ת����������Ŀռ� */
    if (g_rtp_ctrl_tbl[0])
    {
        for (i = 0; i < RTP_TBL_SIZE; i++)
        {
            rtp_write_lock(&g_rtp_ctrl_tbl[0][i].lock);
            if (g_rtp_ctrl_tbl[0][i].cache != NULL)
            {
                kmem_cache_free(g_rtp_cachep, g_rtp_ctrl_tbl[0][i].cache);
                g_rtp_ctrl_tbl[0][i].cache = NULL;
            }
            rtp_write_unlock(&g_rtp_ctrl_tbl[0][i].lock);

            rtp_write_lock(&g_rtp_ctrl_tbl[1][i].lock);
            if (g_rtp_ctrl_tbl[1][i].cache != NULL)
            {
                kmem_cache_free(g_rtp_cachep, g_rtp_ctrl_tbl[1][i].cache);
                g_rtp_ctrl_tbl[1][i].cache = NULL;
            }
            rtp_write_unlock(&g_rtp_ctrl_tbl[1][i].lock);
        }
        
        kfree(g_rtp_ctrl_tbl[0]);
        g_rtp_ctrl_tbl[0] = NULL;

        kfree(g_rtp_ctrl_tbl[1]);
        g_rtp_ctrl_tbl[1] = NULL;
    }

    if (g_rtp_cachep)
    {
        kmem_cache_destroy(g_rtp_cachep);
        g_rtp_cachep = NULL;
    }

    #ifdef RTP_DRIVER_PKT_DISPATCH
    rtp_packet_dispatch_unregister();
    #endif

    return;
}


module_init(rtp_relay_init);
module_exit(rtp_relay_fini);

module_param(g_debug_enable, int, 0444);
module_param(g_dsp_test_mode, int, 0444);
module_param(g_rtp_flow_max_rate, int, 0444);
module_param(g_rtp_check_enable, int, 0444);
module_param(g_rtp_vlan_all_untag, int, 0444);
module_param(g_rtp_qos_pkts_power, int, 0444);

MODULE_ALIAS("rtp-relay");
MODULE_AUTHOR("Dinstar Kyle");
MODULE_DESCRIPTION("rtp relay hook");
MODULE_LICENSE("GPL");


