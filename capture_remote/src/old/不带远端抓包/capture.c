/*
 *  Description : capture module
 *  Date        : 2018
 *  Author      : Mason
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/skbuff.h>
#include <linux/inet.h>

#include "capture.h"


struct capture_mgr_root capture_mgr_head;         /* mgr list head */
static struct sock *capture_nl = NULL;
static int capture_debug = 0;
struct capture_mtu g_mtu[USER_MAX];
struct capture_timer g_capture_timer[USER_MAX];
static unsigned int capture_ticks = 1000;


/* each remote server has it's own mtu value */
unsigned int capture_get_mtu(unsigned int id)
{
    int i = 0;
    for(;i<USER_MAX;i++)
    {
        if(g_mtu[i].taskid == id)
            return g_mtu[i].mtu;        
    }
    return 0;
}

/* set mtu value */
void capture_set_mtu(unsigned int id, unsigned int mtu)
{
    int i = 0;
    for(;i<USER_MAX;i++)
    {
        if(g_mtu[i].taskid == id)
        {
            g_mtu[i].mtu = mtu;
            return ;
        }
    }
    LOG_WARN("mtu set fail, no task \r\n");    
}

/*
 *  get transport layer port
 *  if dir=0,return dport,otherwise return sport
 */ 
unsigned short capture_get_port(const struct sk_buff *skb,int dir)
{
    struct iphdr  *iph  = NULL;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    unsigned short port = 0;
    
    iph = ip_hdr(skb);
    if(!iph)
    {
        LOG_WARN("ip header null \r\n");
        return 0;
    }
    if(iph->protocol == IPPROTO_TCP)
    {
        tcph = tcp_hdr(skb);
        if(!tcph)
        {
            LOG_WARN("tcp header null \r\n");
            return 0;
        }
        if(dir == 0)
        {
            port = ntohs(tcph->dest); 
            tcph = NULL;
            return port;
        }
        else
        {        
            port = ntohs(tcph->source);
            tcph = NULL;
            return port;
        }
    }
    else if(iph->protocol == IPPROTO_UDP)
    {
        udph = udp_hdr(skb);
        if(!udph)
        {
            LOG_WARN("udp header null \r\n");
            return 0;
        }
        if(dir == 0)
        {
            port = ntohs(udph->dest);
            udph = NULL;
            return port;
        }
        else
        {
            port = ntohs(udph->source);
            udph = NULL;
            return port;
        }
    }
    else
        return 0;
}
EXPORT_SYMBOL(capture_get_port);

/* get L4 protocol type */
unsigned int capture_get_transport_protocol(const struct sk_buff *skb)
{
    struct iphdr *iph = NULL;
    iph = ip_hdr(skb);
    if(!iph)
    {
        return 0;
    }
    if(iph->protocol == IPPROTO_TCP)
        return (CAPTURE_TCP);
    if(iph->protocol == IPPROTO_UDP)
        return (CAPTURE_UDP);

    return 0;
}
EXPORT_SYMBOL(capture_get_transport_protocol);

/* 
 * send arp packet 
 * if flag ture then this is output packet
 * if flag false then this is input packet
 * we have to deal it separately
 */
int capture_send_arp(const struct sk_buff *skb, struct capture_info *cache, int output)
{
    struct ethhdr  *oldethh = NULL;    
    struct iphdr   *newiph  = NULL;
    struct udphdr  *newudph = NULL; 
    struct sk_buff *skb_cp  = NULL;
    unsigned int headlen = 0;

    if(output)
        headlen = 42;      /* mac+ip+udp = 42 */
    else
        headlen = 56;      /* mac+ip+udp+mac = 56 */    
    /* if no enough space for new headers, expand it, otherwise just make a copy of it */
	if(skb_headroom(skb) < headlen)
	{
        skb_cp = skb_copy_expand(skb,headlen,0,GFP_ATOMIC);            
        if(!skb_cp)
        {
            LOG_WARN(" realloc skb fail \r\n");
            return -1;
        }
	}
	else
	{
    	skb_cp = skb_copy(skb, GFP_ATOMIC);
    	if(!skb_cp)
	    {
		    LOG_WARN(" copy skb fail \r\n");
		    return -1;
	    }
    }
    
    /*
    * new skb format
     ---------------------------------------------------------------------
     | new mac | new ip | new udp | old mac |              arp           |
     ---------------------------------------------------------------------
     |        new header          |            new data                  |            
     ---------------------------------------------------------------------    
    *
    */

    if(!output)
    {
        /* for input packet */
        skb_push(skb_cp,sizeof(struct ethhdr));
        #if 0
        skb_reset_mac_header(skb_cp);
        oldethh = eth_hdr(skb_cp);
        oldethh->h_proto = htons(ETH_P_ARP);            
        memset(&oldethh->h_dest,0,ETH_ALEN);
        memset(&oldethh->h_source,0,ETH_ALEN); 
        #endif
    }
    
    /* add new ip and udp header */
    skb_push(skb_cp, sizeof(struct iphdr) + sizeof(struct udphdr));    
    skb_reset_network_header(skb_cp);
    skb_set_transport_header(skb_cp,sizeof(struct iphdr));
    newiph = ip_hdr(skb_cp);
    newudph = udp_hdr(skb_cp);

    if((newiph == NULL) || (newudph == NULL))
    {
        LOG_WARN("get ip udp header fail \r\n");
        kfree_skb(skb_cp);
        return -1;
    }

    /*   sport should be zero, because we check output ip packet by sport£¬In case of loop capturing */	
    newudph->source = htons(0);
    /* newudph->source = cache->addr.local_port; */
    newudph->dest = cache->addr.remote_port;
    /* sizeof(struct arphdr) + sizeof(struct udphdr) + sizeof(struct ethhdr) */
    newudph->len = htons(28 + sizeof(struct udphdr) + sizeof(struct ethhdr));
    
    memset(newiph,0,sizeof(struct iphdr));
    newiph->version = 4;
	newiph->ihl = 5;
	newiph->tot_len = htons(ntohs(newudph->len) + sizeof(struct iphdr));
    newiph->frag_off = htons(IP_DF);
    newiph->ttl = 64;
	newiph->protocol = IPPROTO_UDP;	
    newiph->saddr = cache->addr.local_ip.ip;
    newiph->daddr = cache->addr.remote_ip.ip;

    /* disable gso_segment */        
    skb_shinfo(skb_cp)->gso_size = htons(0);

    newudph->check = 0;
    newiph->check = 0;
    skb_cp->csum = 0;
	skb_cp->csum = csum_partial(skb_transport_header(skb_cp), htons(newudph->len), 0);    
	newudph->check = csum_tcpudp_magic(newiph->saddr, newiph->daddr, htons(newudph->len), IPPROTO_UDP, skb_cp->csum);	

    skb_cp->ip_summed = CHECKSUM_NONE;
    if (0 == newudph->check)
    {
	    newudph->check = CSUM_MANGLED_0;
    }
	newiph->check = ip_fast_csum((unsigned char*)newiph, newiph->ihl);
    
    if(ip_route_me_harder(skb_cp, RTN_UNSPEC))
    {
        kfree_skb(skb_cp);
        log_info("ip route failed \r\n");
        return -1;
    }

    ip_send_check(ip_hdr(skb_cp));                                 
    skb_dst_set(skb_cp, (struct dst_entry *)skb_cp->_skb_refdst);  
    dst_hold(skb_dst(skb_cp));
    dst_output(skb_cp);

    return 0;   
}

/* 
 * copy skb and send skb_cp 
 * if isrtp flag is true, old eth header is push already by relay_rtp module, we can
 * skip this.
 * if output flag true, then set old ethh->souce and ethh->dest to 0, because layer 2 header
 * not ready now, so the Layer2 address is meanless,
 */
int capture_send(const struct sk_buff *skb, struct capture_info *cache,int isrtp,int output)
{
    unsigned seq;
    int hh_len;
    int hh_alen;
      
    struct hh_cache *hh = NULL;
    struct neighbour *neigh = NULL;
    struct dst_entry *dst = NULL;
    struct net_device *dev = NULL;
    struct ethhdr *ethh = NULL;

    struct ethhdr  *oldethh = NULL;
    struct iphdr   *oldiph  = NULL;
    struct iphdr   *newiph  = NULL;
    struct udphdr  *newudph = NULL; 
    struct sk_buff *skb_cp  = NULL;
    unsigned int mtu = 0;
    unsigned int headlen = 0;

    if(isrtp)
        headlen = 42;      /* mac+ip+udp = 42 */
    else
        headlen = 56;      /* mac+ip+udp+mac = 56 */
    headlen = 60;    
    /* if no enough space for new headers, expand it, otherwise just make a copy of it */
	if(skb_headroom(skb) < headlen)
	{
        skb_cp = skb_copy_expand(skb,headlen,0,GFP_ATOMIC);            
        if(!skb_cp)
        {
            LOG_WARN(" realloc skb fail \r\n");
            return -1;
        }
	}
	else
	{
    	skb_cp = skb_copy(skb, GFP_ATOMIC);
    	if(!skb_cp)
	    {
		    LOG_WARN(" copy skb fail \r\n");
		    return -1;
	    }
    }

    oldiph = ip_hdr(skb);
    if(!oldiph)
    {
        LOG_WARN("ip header null \r\n");
        kfree_skb(skb_cp);
        return -1;
    }
    
    /*
    * new skb format
     ---------------------------------------------------------------------
     | new mac | new ip | new udp | old mac | old ip| old tcp/udp | data |
     ---------------------------------------------------------------------
     |        new header          |            new data                  |            
     ---------------------------------------------------------------------    

    * we find output packet do not have mac address protocol type
    * so add it manully
    */
    if(!(isrtp))
    {
        if(output)
        {
            dst= skb_dst(skb_cp);
            if(dst)
            {
                dev = dst->dev;
                rcu_read_lock();
                neigh = dst_get_neighbour_noref(dst);
                if(neigh)
                {
                    hh = &neigh->hh;
                    if ((neigh->nud_state & NUD_CONNECTED) && hh->hh_len)
                    {                
                        do {
                            seq = read_seqbegin(&hh->hh_lock);
                            hh_len = hh->hh_len;
                            hh_alen = HH_DATA_ALIGN(hh_len);
                            memcpy(skb_cp->data - hh_alen, hh->hh_data, hh_alen);
                        } while (read_seqretry(&hh->hh_lock, seq));
                        
                        skb_push(skb_cp, hh_len);
                        if(skb_headroom(skb_cp) < 42)
                        {
                            log_info("no enough space for skb, drop it \r\n");
                            kfree_skb(skb_cp);
                            rcu_read_unlock();
                            return -1;
                        }           
                    }
                    else
                    {
                        /* arp cache not match */
                        skb_push(skb_cp,sizeof(struct ethhdr));
                        skb_reset_mac_header(skb_cp);
                        oldethh = eth_hdr(skb_cp);
                        oldethh->h_proto = htons(ETH_P_IP);            
                        memset(oldethh->h_source,0,ETH_ALEN); 
                        memset(oldethh->h_dest,0,ETH_ALEN);
                        if(skb_cp->dev != NULL)
                            memcpy(oldethh->h_source,skb_cp->dev->dev_addr,ETH_ALEN); 
                    }
                }
                rcu_read_unlock();
            }
        }
        else
        {
            skb_push(skb_cp,sizeof(struct ethhdr));
            skb_reset_mac_header(skb_cp);
            oldethh = eth_hdr(skb_cp);
            oldethh->h_proto = htons(ETH_P_IP);            
        }
    }    

    /* add new ip and udp header */
    skb_push(skb_cp, sizeof(struct iphdr) + sizeof(struct udphdr));    
    skb_reset_network_header(skb_cp);
    skb_set_transport_header(skb_cp,sizeof(struct iphdr));
    newiph = ip_hdr(skb_cp);
    newudph = udp_hdr(skb_cp);

    if((newiph == NULL) || (newudph == NULL))
    {
        LOG_WARN("new ip udp header null \r\n");
        kfree_skb(skb_cp);
        return -1;
    }

    /* 
    *   sport should be zero, because we check output ip packet by sport
    *   In case of loop capturing
    */
    memcpy((unsigned char*)newiph,(unsigned char*)oldiph,sizeof(struct iphdr));
    newudph->source = htons(0);
    /* newudph->source = cache->addr.local_port; */
    newudph->dest = cache->addr.remote_port;
    newiph->saddr = cache->addr.local_ip.ip;
    newiph->daddr = cache->addr.remote_ip.ip;

	newiph->ihl = 5;
	newiph->protocol = IPPROTO_UDP;	
    newudph->len = htons(ntohs(oldiph->tot_len) + sizeof(struct udphdr) + sizeof(struct ethhdr));
	newiph->tot_len = htons(ntohs(newudph->len) + sizeof(struct iphdr));
    mtu = capture_get_mtu(cache->taskid);
    
    if(mtu == 0)
    {
        /* default mtu is 1500, at the very beginning */
        if(htons(newiph->tot_len) > 1500)
        {
            newiph->frag_off = 0;   /* ip_fragment will set offset automaticly */
            LOG_DEBUG("default mtu value \r\n");
        }
        else
        {
            newiph->frag_off = htons(IP_DF);
        }
    }
    else 
    {        
        if(htons(newiph->tot_len) > mtu)
        {
            newiph->frag_off = 0;
        }
        else
        {
            newiph->frag_off = htons(IP_DF);
        }        
    }

    /* disable gso_segment */        
    skb_shinfo(skb_cp)->gso_size = htons(0);

    newudph->check = 0;
    newiph->check = 0;
    skb_cp->csum = 0;
	skb_cp->csum = csum_partial(skb_transport_header(skb_cp), htons(newudph->len), 0);    
	newudph->check = csum_tcpudp_magic(newiph->saddr, newiph->daddr, htons(newudph->len), IPPROTO_UDP, skb_cp->csum);	

    skb_cp->ip_summed = CHECKSUM_NONE;
    if (0 == newudph->check)
    {
	    newudph->check = CSUM_MANGLED_0;
    }
	newiph->check = ip_fast_csum((unsigned char*)newiph, newiph->ihl);
    
    if(ip_route_me_harder(skb_cp, RTN_UNSPEC))
    {
        kfree_skb(skb_cp);
        log_info("ip route failed \r\n");
        return -1;
    }

    if(mtu == 0 && (NULL != skb_dst(skb_cp)))
    {
        mtu = dst_mtu(skb_dst(skb_cp));           
        capture_set_mtu(cache->taskid, mtu);
        LOG_DEBUG("set mtu :%u \r\n",mtu);
    }

    ip_send_check(ip_hdr(skb_cp));                                 
    skb_dst_set(skb_cp, (struct dst_entry *)skb_cp->_skb_refdst);  
    dst_hold(skb_dst(skb_cp));
    dst_output(skb_cp);

    return 0;   
}
EXPORT_SYMBOL(capture_send);

/*
 * check skb addr match filter or not
 * return zero match 
 * return nonzero not match
 */
int is_capture_addr_match(const struct iphdr *iph, const struct capture_info *cache)
{
    if(cache->saddr.ip != 0)
    {
        if(iph->saddr == cache->saddr.ip)
        {
            if(cache->daddr.ip != 0)
            {
                if(iph->daddr == cache->daddr.ip)
                {
                    return 0;
                }       
                else
                {
                    return 1;
                }
            }
            return 0;
        }
        else
        {
            return 1;
        }
    }
    else
    {
        if(cache->daddr.ip != 0)
        {
            if(iph->daddr == cache->daddr.ip)
            {
                return 0;
            }
            else
            {
                return 1;
            }
        }
        else
        {
            return 0;
        }
    }
}

/* 
 *  check if local process msg have to be captured
 *  return 0 catch, otherwise don't
 */
int is_capture_localpkt_match(const struct iphdr *iph, const struct capture_info *cache)
{
    /* do not capture local packet */
    if(cache->islocalpkt == 1)
    {
        if((CIP1(iph->saddr) == 10) && (CIP2(iph->saddr) == 251))
        {
            return 1;
        }
        if((CIP1(iph->daddr) == 10) && (CIP2(iph->daddr) == 251))
        {
            return 1;
        }
        if((CIP1(iph->daddr) == 127) && (CIP2(iph->daddr) == 0))
        {
            return 1;
        }
        
    }
    return 0;
}   

/* check if we have to capture this skb by L4 port */
void capture_match_and_send(const struct sk_buff *skb,unsigned short port,int isrtp,int output)
{
    struct iphdr *iph = NULL;
    struct capture_mgr *mgr = NULL;
    struct capture_ctl *ctl = NULL;    
    unsigned int protocol = 0;
    if(isrtp)
    {
        /* rtp packet base on udp */
        protocol = CAPTURE_UDP;
    }
    else        
        protocol = capture_get_transport_protocol(skb);
    iph = ip_hdr(skb);
    if(iph == NULL)
    {
        LOG_WARN("ip header null \r\n");
        return ;
    }
    
    capture_read_lock(&capture_mgr_head.lock);
    if(capture_mgr_head.mgr != NULL)
    {
        /*  check each mgr in the list */
        mgr = capture_mgr_head.mgr;        
        while(mgr != NULL)
        {
             /* check port range */
             if(mgr->ports.min <= port && port <= mgr->ports.max)         
             {
                /* check protocol */
                ctl = mgr->ctl;
                while(ctl != NULL)
                {
                    /* check protocol,if match then check addr */
                    if(protocol & ctl->cache.protocol)
                    {    
                        if(0 == is_capture_addr_match(iph,&(ctl->cache)))
                        {
                            if(0 == is_capture_localpkt_match(iph, &(ctl->cache)))
                            {
                                capture_send(skb,&(ctl->cache),isrtp,output);                                                    
                            }
                        }
                    }
                    ctl = ctl->next_ctl;
                }
             }
             mgr = mgr->next_mgr;
        }        
    }
    capture_read_unlock(&capture_mgr_head.lock); 
    return ;    
}
EXPORT_SYMBOL(capture_match_and_send);

/* capture arp */
void capture_match_and_send_arp(const struct sk_buff * skb,int output)
{
    int i = 0;
    int flag = 0;    
    struct capture_mgr *mgr = NULL;
    struct capture_ctl *ctl = NULL;    
    unsigned int g_captured_id[USER_MAX] = {0};

    capture_read_lock(&capture_mgr_head.lock);
    mgr = capture_mgr_head.mgr;
    /* for each mgr, check ctl block */
    while(mgr != NULL)
    {
        ctl = mgr->ctl;
        /* check each ctl block */
        while(ctl != NULL)
        {
            /* check whether capture arp or not */
            if(ctl->cache.protocol & CAPTURE_ARP)
            {
                /* check if we have sent before */
                flag = 0;
                for(i=0;i<USER_MAX;i++)
                {
                    if(g_captured_id[i] == ctl->cache.taskid)
                    {
                        flag = 1;
                    }
                }
                if(flag == 0)
                {
                    /* record the taskid, in case send more than once */
                    for(i=0;i<USER_MAX;i++)
                    {
                        if(g_captured_id[i] == 0)
                        {
                            g_captured_id[i] = ctl->cache.taskid; 
                        }
                    }
                    /* copy and send */
                    capture_send_arp(skb,&(ctl->cache),output);
                }    
                flag = 0;         
            }
            ctl = ctl->next_ctl;            
        }
        mgr = mgr->next_mgr;
    }   
    capture_read_unlock(&capture_mgr_head.lock);
    return ;
}

/* capture icmp, which do not have port */
void capture_match_and_send_icmp(const struct sk_buff *skb, int output)
{
    int i = 0;
    int flag = 0;    
    struct iphdr *iph = NULL;
    struct capture_mgr *mgr = NULL;
    struct capture_ctl *ctl = NULL;    
    unsigned int g_captured_id[USER_MAX] = {0};

    iph = ip_hdr(skb);
    if(iph == NULL)
    {
        LOG_WARN("ip header null \r\n");
        return ;
    }    
    capture_read_lock(&capture_mgr_head.lock);
    mgr = capture_mgr_head.mgr;
    /* for each mgr, check ctl block */
    while(mgr != NULL)
    {
        ctl = mgr->ctl;
        /* check each ctl block */
        while(ctl != NULL)
        {
            if(ctl->cache.protocol & CAPTURE_ICMP)
            {
                if(0 == is_capture_addr_match(iph,&(ctl->cache)))
                {
                    if(0 == is_capture_localpkt_match(iph,&(ctl->cache)))
                    {
                        /* check if we have sent before */
                        flag = 0;
                        for(i=0;i<USER_MAX;i++)
                        {
                            if(g_captured_id[i] == ctl->cache.taskid)
                            {
                                flag = 1;
                            }
                        }
                        if(flag == 0)
                        {
                            /* record the taskid, in case send more than once */
                            for(i=0;i<USER_MAX;i++)
                            {
                                if(g_captured_id[i] == 0)
                                {
                                   g_captured_id[i] = ctl->cache.taskid; 
                                }
                            }
                            /* copy and send */
                            capture_send(skb,&(ctl->cache),0,output);
                        }    
                        flag = 0;
                    }
                }
            }
            ctl = ctl->next_ctl;            
        }
        mgr = mgr->next_mgr;
    }   
    capture_read_unlock(&capture_mgr_head.lock);
    return ;
}

/* capture input packets */
static unsigned int capture_input_hook(unsigned int hooknum,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph = NULL;
	unsigned short dport = 0;
    unsigned short sport = 0;
    
	iph = ip_hdr(skb);
	if(unlikely(!iph))
	{
		return NF_ACCEPT;
	}

    if(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;    

    /* output hook already capture such packet, so accetp here */
	if(iph->saddr == iph->daddr)
	{
        return NF_ACCEPT;
	}        
    if(iph->protocol == IPPROTO_ICMP)
    {
        capture_match_and_send_icmp(skb,0);
        return NF_ACCEPT;
    }
        
    skb_set_transport_header(skb, (iph->ihl*4));            

    /* get sport, all captured packet with sport(0) */
    sport = capture_get_port(skb,1);
    if(sport == 0)
    {
        return NF_ACCEPT;
    }
    
    dport = capture_get_port(skb,0);
    if(dport != 0)   
    {
        capture_match_and_send(skb,dport,0,0);    
    }  
    
    return NF_ACCEPT;
}
                                     

/* capture output packets by source port */
static unsigned int capture_output_hook(unsigned int hooknum,
			       struct sk_buff *skb,
			       const struct net_device *in,
			       const struct net_device *out,
			       int (*okfn)(struct sk_buff *))
{
	struct iphdr *iph;
	unsigned short sport = 0;	    
	iph = ip_hdr(skb);

	if(unlikely(!iph))
	{
		return NF_ACCEPT;
	}
        
    if(iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP && iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;

    if(iph->protocol == IPPROTO_ICMP)
    {
        capture_match_and_send_icmp(skb,1);
        return NF_ACCEPT;
    }    

    /* if sport=0, let it pass */
    sport = capture_get_port(skb,1);    
    if(sport != 0)
        capture_match_and_send(skb,sport,0,1);

    return NF_ACCEPT;         	
}

static unsigned int capture_arp_input_hook(unsigned int hooknum,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
{
    __be32 sip, tip;
	unsigned char *arp_ptr = NULL;    
    struct arphdr *arph = NULL;
    arph = arp_hdr(skb);
    if(unlikely(!arph))
    {
        log_info("get arp header fail \r\n");
        return NF_ACCEPT;
    }
    if(skb->dev != NULL)
    {
        arp_ptr = (unsigned char *)(arph + 1);
        arp_ptr += (skb->dev)->addr_len;
        memcpy(&sip, arp_ptr, 4);
        arp_ptr += 4;
        arp_ptr += (skb->dev)->addr_len;    
        memcpy(&tip, arp_ptr, 4);
        if(CIP1(sip) == 10 && CIP2(sip) == 251)
            return NF_ACCEPT;
        if(CIP1(tip) == 10 && CIP2(tip) == 251)
            return NF_ACCEPT;
    }

    capture_match_and_send_arp(skb,0);
    return NF_ACCEPT;
}

static unsigned int capture_arp_output_hook(unsigned int hooknum,
                    struct sk_buff *skb,
                    const struct net_device *in,
                    const struct net_device *out,
                    int (*okfn)(struct sk_buff *))
{

    __be32 sip, tip;
    unsigned char *arp_ptr = NULL;    
    struct arphdr *arph = NULL;
    arph = arp_hdr(skb);
    if(unlikely(!arph))
    {
        log_info("get arp header fail \r\n");
        return NF_ACCEPT;
    }
    if(skb->dev != NULL)
    {
        arp_ptr = (unsigned char *)(arph + 1);
        arp_ptr += (skb->dev)->addr_len;
        memcpy(&sip, arp_ptr, 4);
        arp_ptr += 4;
        arp_ptr += (skb->dev)->addr_len;    
        memcpy(&tip, arp_ptr, 4);
        if(CIP1(sip) == 10 && CIP2(sip) == 251)
            return NF_ACCEPT;
        if(CIP1(tip) == 10 && CIP2(tip) == 251)
            return NF_ACCEPT;
    }

    capture_match_and_send_arp(skb,1);
    return NF_ACCEPT;
}

struct nf_hook_ops capture_hook_ops[] = {
	{
		.hook=capture_input_hook,
		.pf=NFPROTO_IPV4,
		.hooknum=NF_INET_PRE_ROUTING,
		.priority=NF_IP_PRI_FIRST + 10,
	},
	{
		.hook=capture_output_hook,
		.pf=NFPROTO_IPV4,
		.hooknum=NF_INET_POST_ROUTING,
		.priority=0,
	},	
	{
        .hook=capture_arp_input_hook,
        .pf=NFPROTO_ARP,
        .hooknum=NF_ARP_IN,
        .priority=0,
	},
	{
        .hook=capture_arp_output_hook,
        .pf=NFPROTO_ARP,
        .hooknum=NF_ARP_OUT,
        .priority=0,
	},	
	{}
};

/* delete capture task by id */
static void capture_netlink_delete(unsigned int taskid)
{
    struct capture_ctl  *ctl     = NULL;
    struct capture_mgr  *mgr     = NULL;
    struct capture_task *task    = NULL;
    struct capture_mgr  *mgr_prv = NULL;
    struct capture_ctl  *ctl_prv = NULL;
    struct capture_task *task_prv= NULL;
    int i = 0;

    /* delete timer */
    for(i=0;i<USER_MAX;i++)
    {
        if(g_capture_timer[i].taskid == taskid)
        {
           g_capture_timer[i].taskid = 0;
           del_timer(&g_capture_timer[i].timer);
           LOG_DEBUG("delete timer, taskid:%u \r\n",taskid);
        }
    }    
    /* delete mtu list */
    for(i=0;i<USER_MAX;i++)
    {
        if(g_mtu[i].taskid == taskid)
        {
            g_mtu[i].taskid = 0;
            g_mtu[i].mtu = 0;
        }
    }
    capture_write_lock(&capture_mgr_head.lock);
    if(capture_mgr_head.mgr == NULL)
    {
        LOG_WARN("no capture task, delete %u fail \r\n",taskid);
        goto end;
    }
    else
    {
       /* first, delete task from tasklist */
       task = capture_mgr_head.task_list;
       task_prv = NULL;
       while(task != NULL)
       {
            /* if taskid match */
            if(task->taskid == taskid)
            {
                if(task->task_next != NULL)
                {
                    if(task_prv == NULL)
                    {
                        capture_mgr_head.task_list = task->task_next;
                    }
                    else
                    {
                        task_prv->task_next = task->task_next;
                    }
                }
                /* next task null */
                else
                {
                    if(task_prv == NULL)
                    {
                        capture_mgr_head.task_list = NULL;
                    }
                    else
                    {
                        task_prv->task_next = NULL;
                    }
                }
                kfree(task);
                task = NULL;
                break;
            }
            /* not match,check next */
            else
            {
                task_prv = task;
                task = task->task_next;
                if(task == NULL)
                {
                    LOG_WARN("delete fail, taskid : %d not exist \r\n",taskid);
                    goto end;
                }
            }
       }
       
       mgr_prv = NULL; 
       mgr = capture_mgr_head.mgr;
       /* check each ctl block under mgr, if match then delete it. then check next mgr */
       while(mgr != NULL)
       {
            ctl_prv = NULL;
            ctl = mgr->ctl;
            /*  check each ctl block */
            while(ctl != NULL)
            {
                /* if match then delete it  */ 
                if(ctl->cache.taskid == taskid)
                {
                    /* have others ctl block */ 
                    if(ctl->next_ctl != NULL)
                    {
                        if(ctl_prv == NULL)
                        {
                            mgr->ctl = ctl->next_ctl;
                        }
                        else
                        {
                            ctl_prv->next_ctl = ctl->next_ctl;
                        }
                    }
                    /* only exist one block */ 
                    else
                    {
                        if(ctl_prv == NULL)
                        {
                            mgr->ctl = NULL;
                        }
                        else
                        {
                            ctl_prv->next_ctl = NULL; 
                        }
                    }
                    log_info("delete ctl block by taskid : %u",ctl->cache.taskid);
                    kfree(ctl);
                    ctl = NULL;
                    /* check next mgr */
                    break;                    
                }
                /* if not match, check next ctl block */ 
                else
                {
                    if(ctl->next_ctl != NULL)
                    {
                        ctl_prv = ctl;
                        ctl = ctl->next_ctl;
                    }   
                    else
                    {
                        /* done with current mgr, check next mgr */ 
                        break;
                    }
                }                
            }
            if(mgr->next_mgr != NULL)
            {
                mgr_prv = mgr;
                mgr = mgr->next_mgr;
            }
            else
            {
                break;
            }
       }
       /* check mgr list, if one without ctl block, delete it  */
       mgr_prv = NULL;
       mgr = capture_mgr_head.mgr;
       while(mgr != NULL)
       {
            /* need delete this mgr */ 
            if(mgr->ctl == NULL)
            {
                /* if we are head of mgr list */ 
                if(mgr->next_mgr == NULL)
                {
                    if(mgr_prv == NULL)
                    {
                        capture_mgr_head.mgr = NULL;
                    }
                    else
                    {
                        mgr_prv->next_mgr = NULL;
                    }
                    log_info("delete mgr, port.min= %u port.max=%u \r\n",mgr->ports.min,mgr->ports.max);
                    kfree(mgr);
                    mgr = NULL;
                    break;
                }
                /* if next mgr exist */
                else
                {
                    if(mgr_prv == NULL)
                    {
                        capture_mgr_head.mgr = mgr->next_mgr;
                        log_info("delete mgr port.min= %u port.max=%u \r\n",mgr->ports.min,mgr->ports.max);                        
                        kfree(mgr);
                        mgr = capture_mgr_head.mgr;
                    }
                    else
                    {
                        mgr_prv->next_mgr = mgr->next_mgr;
                        log_info("delete mgr port.min= %u port.max=%u \r\n",mgr->ports.min,mgr->ports.max);
                        kfree(mgr);
                        mgr = mgr_prv->next_mgr;
                    }
                }
            }
            /* check next mgr */
            else
            {
                if(mgr->next_mgr != NULL)
                {
                    mgr_prv = mgr;
                    mgr = mgr->next_mgr;
                }
                else
                {
                    break;
                }
            }
       }
    }

end:
    capture_write_unlock(&capture_mgr_head.lock);
    log_info("delete taskid:%hu done \r\n",taskid);
    return ;
}

/* capture timer handler*/
void capture_timer_handler(unsigned long taskid)
{
    int i = 0;
    unsigned int id = (unsigned int)taskid;
    capture_netlink_delete(id);
    log_info("time's up, delete task:%hu \r\n",id);
    return ;
}

static void capture_add_timer(unsigned int taskid,unsigned int timeval)
{
    int i = 0;
    for(;i<USER_MAX;i++)
    {
        if(g_capture_timer[i].taskid == taskid)
        {
            LOG_DEBUG("task:%u timer already exist \r\n",taskid);
            return ;
        }        
    }
    for(i=0;i<USER_MAX;i++)
    {
        if(g_capture_timer[i].taskid == 0)
        {
            g_capture_timer[i].taskid = taskid;
            init_timer(&g_capture_timer[i].timer);
            g_capture_timer[i].timer.data = (unsigned long)taskid;
            g_capture_timer[i].timer.expires = jiffies + timeval*60*capture_ticks;
            g_capture_timer[i].timer.function = capture_timer_handler;
            add_timer(&g_capture_timer[i].timer);
            log_info("add timer taskid %u\r\n",taskid);
            return ;
        }
    }
    log_info("add timer fail, too much user \r\n");
    return ;
}

/* add capture ctl block */
static void capture_netlink_add(unsigned int taskid, unsigned int localflag, unsigned int islocalpkt,struct capture_addr *addr, struct capture_filter_nl *filter )
{
    int i = 0;
    unsigned char flag = 0;
    struct capture_mgr    *mgr     = NULL;
    struct capture_ctl    *ctl     = NULL;
    struct capture_task   *task    = NULL;
    struct capture_mgr    *mgr_prv = NULL;
    struct capture_ctl    *ctl_prv = NULL;
    struct capture_task   *task_prv= NULL;    
    /* set default mtu */
    for(;i<USER_MAX;i++)
    {        
        if(g_mtu[i].taskid == taskid)
        {
            /* task already exist, maybe multi filter exist */
            flag = 1;
            break;
        }
    }
    if(flag == 0)
    {
        i = 0;
        for(;i<USER_MAX;i++)
        {
            if(g_mtu[i].taskid == 0)
            {
                g_mtu[i].taskid = taskid;
                g_mtu[i].mtu = 0;
                break;
            }
        }
        if(i == USER_MAX)
            LOG_DEBUG("too much user \r\n");
    }
    capture_write_lock(&capture_mgr_head.lock);
    /* now add mgr and ctl under mgr  */
    mgr = capture_mgr_head.mgr;
    mgr_prv = NULL;    
    while(1)
    {
        if(mgr == NULL)
        {
            /* mgr list head */
            if(mgr_prv == NULL)
            {
                capture_mgr_head.mgr = (struct capture_mgr *)kmalloc(sizeof(struct capture_mgr), GFP_KERNEL);
                /* if mgr create fail */
                if(capture_mgr_head.mgr == NULL)
                {
                    LOG_WARN("new mgr kmalloc fail \r\n");
                    goto end;
                }
                /* if mgr create success */
                else
                {
                    memset(capture_mgr_head.mgr,0,sizeof(struct capture_mgr));
                    mgr = capture_mgr_head.mgr;
                    mgr->ctl = NULL;
                    mgr->next_mgr = NULL;                    
                    mgr->ports.min = filter->min;
                    mgr->ports.max = filter->max;
                    mgr->ctl = (struct capture_ctl *)kmalloc(sizeof(struct capture_ctl), GFP_KERNEL);
                    /* create ctl block fail */
                    if(mgr->ctl == NULL)
                    {
                        LOG_WARN("new ctl kmalloc fail \r\n");
                        kfree(capture_mgr_head.mgr);
                        capture_mgr_head.mgr = NULL;
                        mgr = NULL;
                        goto end;
                    }
                    /* create ctl block success */
                    else
                    {
                        memset(mgr->ctl,0,sizeof(struct capture_ctl));
                        mgr->ctl->cache.taskid = taskid;
                        mgr->ctl->cache.localflag = localflag;
                        mgr->ctl->cache.islocalpkt = islocalpkt;
                        mgr->ctl->cache.protocol = filter->protocol;
                        mgr->ctl->cache.addr.local_port = 0;
                        mgr->ctl->cache.addr.remote_port = addr->remote_port;
                        mgr->ctl->cache.addr.local_ip.ip = addr->local_ip.ip;
                        mgr->ctl->cache.addr.remote_ip.ip = addr->remote_ip.ip;
                        mgr->ctl->cache.saddr.ip = filter->saddr.ip;
                        mgr->ctl->cache.daddr.ip = filter->daddr.ip;
                        mgr->ctl->next_ctl = NULL;
                        log_info("add capture ctl,taskid :%u",taskid);
                        goto next;
                    }
                 }
            }
            /* add mgr at tail */
            else
            {
                mgr = (struct capture_mgr *)kmalloc(sizeof(struct capture_mgr), GFP_KERNEL);
                /* fail to create mgr */
                if(mgr == NULL)
                {
                    LOG_WARN("new mgr kmalloc fail \r\n");
                    goto end;
                }
                /* create mgr success */
                else
                {
                    memset(mgr,0,sizeof(struct capture_mgr));
                    mgr->ctl = NULL;
                    mgr->next_mgr = NULL;
                    mgr->ports.min = filter->min;
                    mgr->ports.max = filter->max;
                    mgr->ctl = (struct capture_ctl *)kmalloc(sizeof(struct capture_ctl), GFP_KERNEL);
                    /* fail to create ctl block */
                    if(mgr->ctl == NULL)
                    {
                        LOG_WARN("new ctl kmalloc fail \r\n");
                        kfree(mgr);
                        mgr = NULL;
                        goto end;
                    }
                    /* create ctl block successfully */
                    else
                    {
                        memset(mgr->ctl,0,sizeof(struct capture_ctl));
                        mgr->ctl->cache.taskid = taskid;
                        mgr->ctl->cache.localflag = localflag;
                        mgr->ctl->cache.islocalpkt = islocalpkt;                        
                        mgr->ctl->cache.protocol = filter->protocol;
                        mgr->ctl->cache.addr.local_port = 0;    /*in case of loop capturing*/
                        mgr->ctl->cache.addr.remote_port = addr->remote_port;
                        mgr->ctl->cache.addr.local_ip.ip = addr->local_ip.ip;
                        mgr->ctl->cache.addr.remote_ip.ip = addr->remote_ip.ip;
                        mgr->ctl->cache.saddr.ip = filter->saddr.ip;
                        mgr->ctl->cache.daddr.ip = filter->daddr.ip;
                        mgr->ctl->next_ctl = NULL;
                        mgr_prv->next_mgr = mgr;
                        log_info("add capture ctl,taskid :%u",taskid);
                        goto next;
                    }
                 }                
            }
        }
        /* if mgr block exist, */
        else
        {
            /* if match then add a ctl block */
            if((mgr->ports.min == filter->min) && (mgr->ports.max == filter->max))
            {
                ctl_prv = NULL;
                ctl = mgr->ctl;
                while(ctl != NULL)
                {
                    if(ctl->cache.taskid == taskid)
                    {
                        LOG_WARN("task already exist, But could be same user \r\n");
                        goto end;
                    }
                    else
                    {
                        ctl_prv = ctl;
                        ctl = ctl->next_ctl;
                    }
                }
                /* add new ctl block */
                ctl = (struct capture_ctl *)kmalloc(sizeof(struct capture_ctl), GFP_KERNEL);
                /* add new ctl block fail */
                if(ctl == NULL)
                {
                    LOG_WARN("new ctl kmalloc fail \r\n");
                    goto end;
                }
                /* if add success */
                else
                {           
                    memset(ctl,0,sizeof(struct capture_ctl));
                    ctl->cache.taskid = taskid;
                    ctl->cache.localflag = localflag;
                    ctl->cache.islocalpkt = islocalpkt;                    
                    ctl->cache.protocol = filter->protocol;
                    ctl->cache.addr.local_port =0;
                    ctl->cache.addr.remote_port = addr->remote_port;
                    ctl->cache.addr.local_ip.ip = addr->local_ip.ip;
                    ctl->cache.addr.remote_ip.ip = addr->remote_ip.ip;
                    ctl->cache.saddr.ip = filter->saddr.ip;
                    ctl->cache.daddr.ip = filter->daddr.ip;
                    ctl->next_ctl = NULL;
                    ctl_prv->next_ctl = ctl;
                    log_info("create task id:%u",taskid);
                    goto next;
                }                
            }
            /* port not match, check next mgr  */
            else
            {
                mgr_prv = mgr;
                mgr = mgr->next_mgr;
            }
        }
    }

next:
    /*
     *  add taskid to tasklist,first check whether exist
     *  check whether task already exist;
     */
    task = capture_mgr_head.task_list;
    if(task == NULL)
    {
        capture_mgr_head.task_list = (struct capture_task *)kmalloc(sizeof(struct capture_task),GFP_KERNEL);
        if(capture_mgr_head.task_list == NULL)
        {
            LOG_WARN("tasklist kmalloc fail \r\n");
            goto end;
        }
        else
        {
            log_info("add new task by id %hu",taskid);
            memset(capture_mgr_head.task_list,0,sizeof(struct capture_task));
            capture_mgr_head.task_list->taskid = taskid;
            capture_mgr_head.task_list->task_next = NULL;            
        }
    }
    else
    {
        task_prv = task;
        while(task != NULL)
        {
            if(task->taskid == taskid)
            {
                LOG_WARN("task already exist, Maybe just the same task \r\n");
                goto end;
            }
            else
            {
                task_prv = task;
                task = task->task_next;
            }
        }
        task = (struct capture_task *)kmalloc(sizeof(struct capture_task),GFP_KERNEL);
        if(!task)
        {
            LOG_WARN("task kmalloc fail \r\n");
            goto end;
        }
        else
        {
            log_info("add new task by id %hu",taskid);      
            memset(task,0,sizeof(struct capture_task));
            task_prv->task_next = task;
            task->taskid = taskid;
            task->task_next = NULL;
        }
    }
    
end:
    capture_write_unlock(&capture_mgr_head.lock);
    return ;
}


/* delete all capture task */
static void capture_netlink_delete_all(void)
{
    struct capture_task *task_head = NULL;
    struct capture_task *task_prv = NULL;    
    struct capture_task *task = NULL;    

    /* first, get all task from tasklist */
    capture_read_lock(&capture_mgr_head.lock);
    task = capture_mgr_head.task_list;
    if(capture_mgr_head.task_list == NULL)
    {
        capture_read_unlock(&capture_mgr_head.lock);
        LOG_DEBUG("module exit, delete all capture task \r\n");
        return ;
    }
    while(task != NULL)
    {
        if(task_prv == NULL)
        {
            task_head = (struct capture_task *)kmalloc(sizeof(struct capture_task), GFP_KERNEL);
            if(!task_head)
            {
                LOG_WARN("kmalloc tasklist fail,delete all task fail \r\n");
                capture_read_unlock(&capture_mgr_head.lock);   
                return ;        
            }
            else
            {
                task_head->taskid = task->taskid;
                task_head->task_next = NULL;
                task_prv = task_head;
            }
        }
        else
        {
            task_prv->task_next = (struct capture_task *)kmalloc(sizeof(struct capture_task), GFP_KERNEL);
            if(task_prv->task_next == NULL)
            {
                LOG_WARN("kmalloc tasklist fail \r\n");
                break;
            }
            else
            {
                task_prv = task_prv->task_next;
                task_prv->taskid = task->taskid;
                task_prv->task_next = NULL;
            }
        }
        task = task->task_next;
    }
    capture_read_unlock(&capture_mgr_head.lock);   

    /* delete capture task */
    task = task_head;   
    while(task != NULL )
    {
        capture_netlink_delete(task->taskid);        
        task = task->task_next;
    }
    /* free memory */
    task = task_head;
    while(task != NULL)
    {
        if(task->task_next != NULL)
        {
            task_head = task->task_next;
            kfree(task);
            task = task_head;
        }
        else
        {
            kfree(task);
            task = NULL;
        }                
    }
    task = NULL;
    task_head = NULL;
    task_prv = NULL;
    LOG_DEBUG("delete all task done \r\n");

}

/* receive netlink message */
static int capture_netlink_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int index = 0;
    int users = 0;
    int filter_count;
    int filter_len;
    unsigned int *taskid = NULL;
    struct capture_task *tasklist = NULL;
    struct capture_task_info_nl *task = NULL;
    filter_len = sizeof(struct capture_filter_nl);
    switch(nlh->nlmsg_type){
        /* add capture task */
        case CAPTURE_ADD :
            task = (struct capture_task_info_nl *)NLMSG_DATA(nlh);            
            filter_count = (nlh->nlmsg_len - NLMSG_HDRLEN - sizeof(struct capture_addr) - sizeof(int)*4)/filter_len;
            /* check if taskid already exsit in tasklist or invalid,if not then add */                          
            if(task->taskid == 0)
            {
                LOG_WARN("waring. taskid invalidï¼Œtaskid: %u \r\n",task->taskid);
                return -1;
            }
            
          
            capture_read_lock(&capture_mgr_head.lock);
            tasklist = capture_mgr_head.task_list;
            /* get user number */
            while(tasklist != NULL)
            {
                users++;
                tasklist = tasklist->task_next;
            }
            if(users > USER_MAX)
            {
                LOG_WARN("too much users won't add \r\n");
                capture_read_unlock(&capture_mgr_head.lock);
                return -1;
            }
            tasklist = capture_mgr_head.task_list;            
            while(tasklist != NULL)
            {
                if(tasklist->taskid == task->taskid)
                {
                    LOG_WARN("task already exist,won't add new task \r\n");
                    capture_read_unlock(&capture_mgr_head.lock);
                    return -1;
                }
                else
                {
                    tasklist = tasklist->task_next;
                }                
            }            
            capture_read_unlock(&capture_mgr_head.lock);
          
            /* check port range, only min <= max is valid */
            index = 0;    
            while(index < filter_count)
            {
                  /* port 0 reserved for packet filtering */
                  if(task->filter[index].min == 0)
                  {
                      task->filter[index].min = 1;
                  }

                  if(task->filter[index].min > task->filter[index].max)
                  {
                      LOG_WARN("invalid port range min:%hu > max:%hu",task->filter[index].min,task->filter[index].max);
                      return -1;                        
                  }
                  /* add filter one by one */                  
                  (void)capture_netlink_add(task->taskid,task->localflag,task->islocalpkt,&task->addr,&task->filter[index]);    

                  log_info("add task: \n"
                        "====================\n"
                        "task    id   :%u \n" 
                        "task    remoteserver :%u \n"                         
                        "task    timer:%u \n"
                        "task    ignorelogs:%u \n"
                        "local   port :%hu \n"
                        "remote  port :%hu \n"                        
                        "local   addr :%d:%d:%d:%d:%hu \n"
                        "remote  addr :%d:%d:%d:%d:%hu \n"
                        "min:%hu ~ max:%hu \n"                      
                        "protocol     :%u \n"
                        "saddr        :%d:%d:%d:%d \n"
                        "daddr        :%d:%d:%d:%d \n"
                        "====================\r\n",
                    task->taskid,task->localflag,task->timerval,task->islocalpkt,task->addr.local_port,ntohs(task->addr.remote_port),
                    CIP1(task->addr.local_ip),CIP2(task->addr.local_ip),CIP3(task->addr.local_ip),CIP4(task->addr.local_ip),ntohs(0),
                    CIP1(task->addr.remote_ip),CIP2(task->addr.remote_ip),CIP3(task->addr.remote_ip),CIP4(task->addr.remote_ip),ntohs(task->addr.remote_port),                    
                    task->filter[index].min,task->filter[index].max,
                    task->filter[index].protocol,
                    CIP1(task->filter[index].saddr),CIP2(task->filter[index].saddr),CIP3(task->filter[index].saddr),CIP4(task->filter[index].saddr),
                    CIP1(task->filter[index].daddr),CIP2(task->filter[index].daddr),CIP3(task->filter[index].daddr),CIP4(task->filter[index].daddr));
                  index++;

            }
            /* add timer */
            if(task->timerval == 0)
            {
                LOG_WARN("timeval invalid :%u, set to default 1 \r\n",task->timerval);
                task->timerval = 1;
            }
            capture_add_timer(task->taskid,task->timerval);
            break;
        /* delete task by id */    
        case CAPTURE_DELETE :
            taskid = (unsigned int *)NLMSG_DATA(nlh);
            /*
             * if taskid exist in tasklist, then delete it
             * else just send a warning
             */
            capture_read_lock(&capture_mgr_head.lock);
            tasklist = capture_mgr_head.task_list;
            while(tasklist != NULL)
            {
                if(tasklist->taskid != *taskid)
                {
                    tasklist = tasklist->task_next;
                }                
                else
                {
                    capture_read_unlock(&capture_mgr_head.lock);             
                    capture_netlink_delete(*taskid);
                    log_info("delete capture task id:%hu \r\n", *taskid);                    
                    return 0;
                }
            }
            capture_read_unlock(&capture_mgr_head.lock);                         
            LOG_WARN("task :%hu not exist \r\n",*taskid);
            break;
        default:
            LOG_WARN("unrecognized netlink message type : %u \r\n",nlh->nlmsg_type);
            break;
    }
    
    return 0;
}   

static void capture_netlink_rcv(struct sk_buff *skb)
{
    int res;
	res = netlink_rcv_skb(skb, &capture_netlink_rcv_msg);

    return;
}


static int __init capture_init(void)
{	   
    unsigned long ticks_start, ticks;
    /* g_hz_tickes value init */
    ticks_start = jiffies;
    msleep(10);
    ticks = jiffies - ticks_start;

    if (ticks >= 10)
    {
        capture_ticks = 1000;
    }
    else
    {    
        capture_ticks = 100;
    }

    memset(&g_mtu,0,sizeof(struct capture_mtu)*USER_MAX);
    /* init mgr list head */
    rwlock_init(&capture_mgr_head.lock);
    capture_mgr_head.mgr = NULL;
    capture_mgr_head.task_list = NULL;

    /* initilize netlink module */
	capture_nl = netlink_kernel_create(&init_net, NETLINK_CAPTURE_MODULE, 0, capture_netlink_rcv, NULL, THIS_MODULE);
    if(!capture_nl)
    {
        LOG_WARN("netlink capture module init fail \r\n");
        return -1;
    }

    /* initialize netfilter hooks */
	if(nf_register_hooks(capture_hook_ops,ARRAY_SIZE(capture_hook_ops))!=0)
	{
		LOG_WARN("netfilter register fail");
		return -1;
	}
	log_info("capture module init \r\n");
	return 0;
}

static void __exit capture_exit(void)
{ 
    /* unregister netfilter hooks */
	nf_unregister_hooks(capture_hook_ops,ARRAY_SIZE(capture_hook_ops));
	if(capture_nl)
	{
        /* unregister netlink module */
        netlink_kernel_release(capture_nl);
        capture_nl = NULL;
	}
    /* delete all capture task */
    capture_netlink_delete_all();
    
	log_info("capture module exit \r\n");
	return ;
}

module_init(capture_init)
module_exit(capture_exit)

module_param(capture_debug, int, 0444);


MODULE_ALIAS("capture");
MODULE_AUTHOR("Mason");
MODULE_DESCRIPTION("capture module");
MODULE_LICENSE("GPL");
