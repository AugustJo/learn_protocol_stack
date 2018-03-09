/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The Internet Protocol (IP) output module.
 *
 * Version:	$Id: ip_output.c,v 1.100 2002/02/01 22:01:03 davem Exp $
 *
 * Authors:	Ross Biro, <bir7@leland.Stanford.Edu>
 *		Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *		Donald Becker, <becker@super.org>
 *		Alan Cox, <Alan.Cox@linux.org>
 *		Richard Underwood
 *		Stefan Becker, <stefanb@yello.ping.de>
 *		Jorge Cwik, <jorge@laser.satlink.net>
 *		Arnt Gulbrandsen, <agulbra@nvg.unit.no>
 *		Hirokazu Takahashi, <taka@valinux.co.jp>
 *
 *	See ip_input.c for original log
 *
 *	Fixes:
 *		Alan Cox	:	Missing nonblock feature in ip_build_xmit.
 *		Mike Kilburn	:	htons() missing in ip_build_xmit.
 *		Bradford Johnson:	Fix faulty handling of some frames when 
 *					no route is found.
 *		Alexander Demenshin:	Missing sk/skb free in ip_queue_xmit
 *					(in case if packet not accepted by
 *					output firewall rules)
 *		Mike McLagan	:	Routing by source
 *		Alexey Kuznetsov:	use new route cache
 *		Andi Kleen:		Fix broken PMTU recovery and remove
 *					some redundant tests.
 *	Vitaly E. Lavrov	:	Transparent proxy revived after year coma.
 *		Andi Kleen	: 	Replace ip_reply with ip_send_reply.
 *		Andi Kleen	:	Split fast and slow ip_build_xmit path 
 *					for decreased register pressure on x86 
 *					and more readibility. 
 *		Marc Boucher	:	When call_out_firewall returns FW_QUEUE,
 *					silently drop skb instead of failing with -EPERM.
 *		Detlev Wengorz	:	Copy protocol for fragments.
 *		Hirokazu Takahashi:	HW checksumming for outgoing UDP
 *					datagrams.
 *		Hirokazu Takahashi:	sendfile() on UDP works now.
 */

#include <asm/uaccess.h>
#include <asm/system.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/config.h>

#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/proc_fs.h>
#include <linux/stat.h>
#include <linux/init.h>

#include <net/snmp.h>
#include <net/ip.h>
#include <net/protocol.h>
#include <net/route.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/arp.h>
#include <net/icmp.h>
#include <net/raw.h>
#include <net/checksum.h>
#include <net/inetpeer.h>
#include <net/checksum.h>
#include <linux/igmp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/mroute.h>
#include <linux/netlink.h>

/*
 *      Shall we try to damage output packets if routing dev changes?
 */

int sysctl_ip_dynaddr;
int sysctl_ip_default_ttl = IPDEFTTL;

/* Generate a checksum for an outgoing IP datagram. */
__inline__ void ip_send_check(struct iphdr *iph)
{
	iph->check = 0;
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);
}

/* dev_loopback_xmit for use with netfilter. */
static int ip_dev_loopback_xmit(struct sk_buff *newskb)
{
	newskb->mac.raw = newskb->data;
	__skb_pull(newskb, newskb->nh.raw - newskb->data);
	newskb->pkt_type = PACKET_LOOPBACK;
	newskb->ip_summed = CHECKSUM_UNNECESSARY;
	BUG_TRAP(newskb->dst);

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_loopback_xmit(newskb);
#endif
	netif_rx(newskb);
	return 0;
}

static inline int ip_select_ttl(struct inet_opt *inet, struct dst_entry *dst)
{
	int ttl = inet->uc_ttl;

	if (ttl < 0)
		ttl = dst_metric(dst, RTAX_HOPLIMIT);
	return ttl;
}

/* 
 *		Add an ip header to a skbuff and send it out.
 *
 */
int ip_build_and_send_pkt(struct sk_buff *skb, struct sock *sk,
			  u32 saddr, u32 daddr, struct ip_options *opt)
{
	struct inet_opt *inet = inet_sk(sk);
	struct rtable *rt = (struct rtable *)skb->dst;
	struct iphdr *iph;

	/* Build the IP header. */
	if (opt)
		iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr) + opt->optlen);
	else
		iph=(struct iphdr *)skb_push(skb,sizeof(struct iphdr));

	iph->version  = 4;
	iph->ihl      = 5;
	iph->tos      = inet->tos;
	if (ip_dont_fragment(sk, &rt->u.dst))
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->daddr    = rt->rt_dst;
	iph->saddr    = rt->rt_src;
	iph->protocol = sk->sk_protocol;
	iph->tot_len  = htons(skb->len);
	ip_select_ident(iph, &rt->u.dst, sk);
	skb->nh.iph   = iph;

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, daddr, rt, 0);
	}
	ip_send_check(iph);

	skb->priority = sk->sk_priority;

	/* Send it out. */
	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);
}

static inline int ip_finish_output2(struct sk_buff *skb)
{
	struct dst_entry *dst = skb->dst;
	struct hh_cache *hh = dst->hh;
	struct net_device *dev = dst->dev;
	int hh_len = LL_RESERVED_SPACE(dev);

	/* Be paranoid, rather than too clever. */
	if (unlikely(skb_headroom(skb) < hh_len && dev->hard_header)) {
		struct sk_buff *skb2;

		skb2 = skb_realloc_headroom(skb, LL_RESERVED_SPACE(dev));
		if (skb2 == NULL) {
			kfree_skb(skb);
			return -ENOMEM;
		}
		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);
		kfree_skb(skb);
		skb = skb2;
	}

#ifdef CONFIG_NETFILTER_DEBUG
	nf_debug_ip_finish_output2(skb);
#endif /*CONFIG_NETFILTER_DEBUG*/

	if (hh) {
		int hh_alen;

		read_lock_bh(&hh->hh_lock);
		hh_alen = HH_DATA_ALIGN(hh->hh_len);
  		memcpy(skb->data - hh_alen, hh->hh_data, hh_alen);
		read_unlock_bh(&hh->hh_lock);
	        skb_push(skb, hh->hh_len);
		return hh->hh_output(skb);
	} else if (dst->neighbour)
		return dst->neighbour->output(skb);

	if (net_ratelimit())
		printk(KERN_DEBUG "ip_finish_output2: No header cache and no neighbour!\n");
	kfree_skb(skb);
	return -EINVAL;
}

int ip_finish_output(struct sk_buff *skb)
{
	struct net_device *dev = skb->dst->dev;

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK(PF_INET, NF_IP_POST_ROUTING, skb, NULL, dev,
		       ip_finish_output2);
}

int ip_mc_output(struct sk_buff *skb)
{
	struct sock *sk = skb->sk;
	struct rtable *rt = (struct rtable*)skb->dst;
	struct net_device *dev = rt->u.dst.dev;

	/*
	 *	If the indicated interface is up and running, send the packet.
	 */
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	/*
	 *	Multicasts are looped back for other local users
	 */

	if (rt->rt_flags&RTCF_MULTICAST) {
		if ((!sk || inet_sk(sk)->mc_loop)
#ifdef CONFIG_IP_MROUTE
		/* Small optimization: do not loopback not local frames,
		   which returned after forwarding; they will be  dropped
		   by ip_mr_input in any case.
		   Note, that local frames are looped back to be delivered
		   to local recipients.

		   This check is duplicated in ip_mr_input at the moment.
		 */
		    && ((rt->rt_flags&RTCF_LOCAL) || !(IPCB(skb)->flags&IPSKB_FORWARDED))
#endif
		) {
			struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
			if (newskb)
				NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
					newskb->dev, 
					ip_dev_loopback_xmit);
		}

		/* Multicasts with ttl 0 must not go beyond the host */

		if (skb->nh.iph->ttl == 0) {
			kfree_skb(skb);
			return 0;
		}
	}

	if (rt->rt_flags&RTCF_BROADCAST) {
		struct sk_buff *newskb = skb_clone(skb, GFP_ATOMIC);
		if (newskb)
			NF_HOOK(PF_INET, NF_IP_POST_ROUTING, newskb, NULL,
				newskb->dev, ip_dev_loopback_xmit);
	}

	if (skb->len > dst_pmtu(&rt->u.dst))
		return ip_fragment(skb, ip_finish_output);
	else
		return ip_finish_output(skb);
}

int ip_output(struct sk_buff *skb)
{
	IP_INC_STATS(IPSTATS_MIB_OUTREQUESTS);

	if (skb->len > dst_pmtu(skb->dst) && !skb_shinfo(skb)->tso_size)
		return ip_fragment(skb, ip_finish_output);
	else
		return ip_finish_output(skb);
}

int ip_queue_xmit(struct sk_buff *skb, int ipfragok)			//tcp 和 sctp 使用
{
	struct sock *sk = skb->sk;
	struct inet_opt *inet = inet_sk(sk);			//可能是前期分配了inet_sock的空间
	struct ip_options *opt = inet->opt;
	struct rtable *rt;
	struct iphdr *iph;

	/* Skip all of this if the packet is already routed,
	 * f.e. by something like SCTP.
	 */
	rt = (struct rtable *) skb->dst;
	if (rt != NULL)		//已经被设定正确路由信息，无需查询路由表 (SCTP)
		goto packet_routed;

	/* Make sure we can route this packet. */		//sk(sock)由上层协议设置
	rt = (struct rtable *)__sk_dst_check(sk, 0);	//检查sk是否缓存了一条路径
	if (rt == NULL) {
		u32 daddr;

		/* Use correct destination address if we have options. */
		daddr = inet->daddr;
		if(opt && opt->srr)
			daddr = opt->faddr;				//如果设置了srr 把下一跳地址设为目的地址

		{
			struct flowi fl = { .oif = sk->sk_bound_dev_if,
					    .nl_u = { .ip4_u =
						      { .daddr = daddr,
							.saddr = inet->saddr,
							.tos = RT_CONN_FLAGS(sk) } },
					    .proto = sk->sk_protocol,
					    .uli_u = { .ports =
						       { .sport = inet->sport,
							 .dport = inet->dport } } };

			/* If this fails, retransmit mechanism of transport layer will
			 * keep trying until route appears or the connection times
			 * itself out.
			 */
			if (ip_route_output_flow(&rt, &fl, sk, 0))		//查询路由系统, 找到下一跳地址
				goto no_route;
		}
		__sk_dst_set(sk, &rt->u.dst);	//重新设置sk->sk_dst_cache缓存
		tcp_v4_setup_caps(sk, &rt->u.dst);
	}
	skb->dst = dst_clone(&rt->u.dst);	//加一次引用

packet_routed:
	if (opt && opt->is_strictroute && rt->rt_dst != rt->rt_gateway)		//严格路由 如果下一跳与路由表不符则丢包
		goto no_route;

	/* 拥有传输封包所有信息, 构建ip报头 */
	iph = (struct iphdr *) skb_push(skb, sizeof(struct iphdr) + (opt ? opt->optlen : 0));	//skb从L4层传来，只包含ip有效载荷, skb->data之前指向L3有效载荷, 现在前移指向ip报头开端
	*((__u16 *)iph)	= htons((4 << 12) | (5 << 8) | (inet->tos & 0xff)); //设定 版本 报头长度 TOS (共享一个16bit)
	iph->tot_len = htons(skb->len);			//ip数据报总长度
	if (ip_dont_fragment(sk, &rt->u.dst) && !ipfragok)
		iph->frag_off = htons(IP_DF);
	else
		iph->frag_off = 0;
	iph->ttl      = ip_select_ttl(inet, &rt->u.dst);
	iph->protocol = sk->sk_protocol;
	iph->saddr    = rt->rt_src;
	iph->daddr    = rt->rt_dst;
	skb->nh.iph   = iph;
	/* Transport layer set skb->h.foo itself. */

	if (opt && opt->optlen) {
		iph->ihl += opt->optlen >> 2;		//如果含有选项, 重新设置报头长度
		ip_options_build(skb, opt, inet->daddr, rt, 0);		
	}

	ip_select_ident_more(iph, &rt->u.dst, sk, skb_shinfo(skb)->tso_segs);		//判断ip是否分片(编号相同, 偏移不同？)

	/* Add an IP checksum. */
	ip_send_check(iph);

	skb->priority = sk->sk_priority;		//不同优先级排入不同外出队列

	return NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, rt->u.dst.dev,
		       dst_output);

no_route:
	IP_INC_STATS(IPSTATS_MIB_OUTNOROUTES);
	kfree_skb(skb);
	return -EHOSTUNREACH;
}


static void ip_copy_metadata(struct sk_buff *to, struct sk_buff *from)
{
	to->pkt_type = from->pkt_type;
	to->priority = from->priority;
	to->protocol = from->protocol;
	to->security = from->security;
	to->dst = dst_clone(from->dst);
	to->dev = from->dev;

	/* Copy the flags to each fragment. */
	IPCB(to)->flags = IPCB(from)->flags;

#ifdef CONFIG_NET_SCHED
	to->tc_index = from->tc_index;
#endif
#ifdef CONFIG_NETFILTER
	to->nfmark = from->nfmark;
	to->nfcache = from->nfcache;
	/* Connection association is same as pre-frag packet */
	nf_conntrack_put(to->nfct);
	to->nfct = from->nfct;
	nf_conntrack_get(to->nfct);
	to->nfctinfo = from->nfctinfo;
#ifdef CONFIG_BRIDGE_NETFILTER
	nf_bridge_put(to->nf_bridge);
	to->nf_bridge = from->nf_bridge;
	nf_bridge_get(to->nf_bridge);
#endif
#ifdef CONFIG_NETFILTER_DEBUG
	to->nf_debug = from->nf_debug;
#endif
#endif
}

/*
 *	This IP datagram is too large to be sent in one piece.  Break it up into
 *	smaller pieces (each of size equal to IP header plus
 *	a block of the data of the original IP data part) that will yet fit in a
 *	single device frame, and queue such a frame for sending.
 */

int ip_fragment(struct sk_buff *skb, int (*output)(struct sk_buff*))
{
	struct iphdr *iph;
	int raw = 0;
	int ptr;
	struct net_device *dev;
	struct sk_buff *skb2;
	unsigned int mtu, hlen, left, len, ll_rs;
	int offset;
	int not_last_frag;
	struct rtable *rt = (struct rtable*)skb->dst;
	int err = 0;

	dev = rt->u.dst.dev;

	/*
	 *	Point into the IP datagram header.
	 */

	iph = skb->nh.iph;

	if (unlikely((iph->frag_off & htons(IP_DF)) && !skb->local_df)) {
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED,
			  htonl(dst_pmtu(&rt->u.dst)));
		kfree_skb(skb);
		return -EMSGSIZE;
	}

	/*
	 *	Setup starting values.
	 */

	hlen = iph->ihl * 4;
	mtu = dst_pmtu(&rt->u.dst) - hlen;	/* Size of data space */

	/* When frag_list is given, use it. First, check its validity:
	 * some transformers could create wrong frag_list or break existing
	 * one, it is not prohibited. In this case fall back to copying.
	 *
	 * LATER: this step can be merged to real generation of fragments,
	 * we can switch to copy when see the first bad fragment.
	 */
	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *frag;
		int first_len = skb_pagelen(skb);

		if (first_len - hlen > mtu ||
		    ((first_len - hlen) & 7) ||
		    (iph->frag_off & htons(IP_MF|IP_OFFSET)) ||
		    skb_cloned(skb))
			goto slow_path;

		for (frag = skb_shinfo(skb)->frag_list; frag; frag = frag->next) {
			/* Correct geometry. */
			if (frag->len > mtu ||
			    ((frag->len & 7) && frag->next) ||
			    skb_headroom(frag) < hlen)
			    goto slow_path;

			/* Partially cloned skb? */
			if (skb_shared(frag))
				goto slow_path;
		}

		/* Everything is OK. Generate! */

		err = 0;
		offset = 0;
		frag = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;
		skb->data_len = first_len - skb_headlen(skb);
		skb->len = first_len;
		iph->tot_len = htons(first_len);
		iph->frag_off |= htons(IP_MF);
		ip_send_check(iph);

		for (;;) {
			/* Prepare header of the next frame,
			 * before previous one went down. */
			if (frag) {
				frag->h.raw = frag->data;
				frag->nh.raw = __skb_push(frag, hlen);
				memcpy(frag->nh.raw, iph, hlen);
				iph = frag->nh.iph;
				iph->tot_len = htons(frag->len);
				ip_copy_metadata(frag, skb);
				if (offset == 0)
					ip_options_fragment(frag);
				offset += skb->len - hlen;
				iph->frag_off = htons(offset>>3);
				if (frag->next != NULL)
					iph->frag_off |= htons(IP_MF);
				/* Ready, complete checksum */
				ip_send_check(iph);
			}

			err = output(skb);

			if (err || !frag)
				break;

			skb = frag;
			frag = skb->next;
			skb->next = NULL;
		}

		if (err == 0) {
			IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
			return 0;
		}

		while (frag) {
			skb = frag->next;
			kfree_skb(frag);
			frag = skb;
		}
		IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
		return err;
	}

slow_path:
	left = skb->len - hlen;		/* Space per frame */
	ptr = raw + hlen;		/* Where to start from */

#ifdef CONFIG_BRIDGE_NETFILTER
	/* for bridged IP traffic encapsulated inside f.e. a vlan header,
	 * we need to make room for the encapsulating header */
	ll_rs = LL_RESERVED_SPACE_EXTRA(rt->u.dst.dev, nf_bridge_pad(skb));
	mtu -= nf_bridge_pad(skb);
#else
	ll_rs = LL_RESERVED_SPACE(rt->u.dst.dev);
#endif
	/*
	 *	Fragment the datagram.
	 */

	offset = (ntohs(iph->frag_off) & IP_OFFSET) << 3;
	not_last_frag = iph->frag_off & htons(IP_MF);

	/*
	 *	Keep copying data until we run out.
	 */

	while(left > 0)	{
		len = left;
		/* IF: it doesn't fit, use 'mtu' - the data space left */
		if (len > mtu)
			len = mtu;
		/* IF: we are not sending upto and including the packet end
		   then align the next start on an eight byte boundary */
		if (len < left)	{
			len &= ~7;
		}
		/*
		 *	Allocate buffer.
		 */

		if ((skb2 = alloc_skb(len+hlen+ll_rs, GFP_ATOMIC)) == NULL) {
			NETDEBUG(printk(KERN_INFO "IP: frag: no memory for new fragment!\n"));
			err = -ENOMEM;
			goto fail;
		}

		/*
		 *	Set up data on packet
		 */

		ip_copy_metadata(skb2, skb);
		skb_reserve(skb2, ll_rs);
		skb_put(skb2, len + hlen);
		skb2->nh.raw = skb2->data;
		skb2->h.raw = skb2->data + hlen;

		/*
		 *	Charge the memory for the fragment to any owner
		 *	it might possess
		 */

		if (skb->sk)
			skb_set_owner_w(skb2, skb->sk);

		/*
		 *	Copy the packet header into the new buffer.
		 */

		memcpy(skb2->nh.raw, skb->data, hlen);

		/*
		 *	Copy a block of the IP datagram.
		 */
		if (skb_copy_bits(skb, ptr, skb2->h.raw, len))
			BUG();
		left -= len;

		/*
		 *	Fill in the new header fields.
		 */
		iph = skb2->nh.iph;
		iph->frag_off = htons((offset >> 3));

		/* ANK: dirty, but effective trick. Upgrade options only if
		 * the segment to be fragmented was THE FIRST (otherwise,
		 * options are already fixed) and make it ONCE
		 * on the initial skb, so that all the following fragments
		 * will inherit fixed options.
		 */
		if (offset == 0)
			ip_options_fragment(skb);

		/*
		 *	Added AC : If we are fragmenting a fragment that's not the
		 *		   last fragment then keep MF on each bit
		 */
		if (left > 0 || not_last_frag)
			iph->frag_off |= htons(IP_MF);
		ptr += len;
		offset += len;

		/*
		 *	Put this fragment into the sending queue.
		 */

		IP_INC_STATS(IPSTATS_MIB_FRAGCREATES);

		iph->tot_len = htons(len + hlen);

		ip_send_check(iph);

		err = output(skb2);
		if (err)
			goto fail;
	}
	kfree_skb(skb);
	IP_INC_STATS(IPSTATS_MIB_FRAGOKS);
	return err;

fail:
	kfree_skb(skb); 
	IP_INC_STATS(IPSTATS_MIB_FRAGFAILS);
	return err;
}

int
ip_generic_getfrag(void *from, char *to, int offset, int len, int odd, struct sk_buff *skb)
{
	struct iovec *iov = from;

	if (skb->ip_summed == CHECKSUM_HW) {
		if (memcpy_fromiovecend(to, iov, offset, len) < 0)
			return -EFAULT;
	} else {
		unsigned int csum = 0;
		if (csum_partial_copy_fromiovecend(to, iov, offset, len, &csum) < 0)
			return -EFAULT;
		skb->csum = csum_block_add(skb->csum, csum, odd);
	}
	return 0;
}

static inline unsigned int
csum_page(struct page *page, int offset, int copy)
{
	char *kaddr;
	unsigned int csum;
	kaddr = kmap(page);
	csum = csum_partial(kaddr + offset, copy, 0);
	kunmap(page);
	return csum;
}

/*
 *	ip_append_data() and ip_append_page() can make one large IP datagram
 *	from many pieces of data. Each pieces will be holded on the socket
 *	until ip_push_pending_frames() is called. Each piece can be a page
 *	or non-page data.
 *	
 *	Not only UDP, other transport protocols - e.g. raw sockets - can use
 *	this interface potentially.
 *
 *	LATER: length must be adjusted by pad at tail, when it is required.
 */
int ip_append_data(struct sock *sk,							//将数据放在大小合适的缓冲区中，后续函数借此构成一些片段，提高效率
		   int getfrag(void *from, char *to, int offset, int len,
			       int odd, struct sk_buff *skb),
		   void *from, 		//from: 指向L4层载荷的指针
		   int length, 		//length: 要传输的数据量(L4报头和载荷长度    )也表示剩余数据量
		   int transhdrlen,					//transhdrlen: L4报头长度
		   struct ipcm_cookie *ipc, 
		   struct rtable *rt,		//rt: 路由表缓存项目			ipc: 正确转发封包所必须的信息
		   unsigned int flags)			//flag: MSG_MORE MSG_DONTWAIT MSG_PROBE
{
	struct inet_opt *inet = inet_sk(sk);
	struct sk_buff *skb;

	struct ip_options *opt = NULL;
	int hh_len;
	int exthdrlen;	//exthdrlen: 外部报头len	(IPsec报头)
	int mtu;
	int copy;		//可用空间量
	int err;
	int offset = 0;
	unsigned int maxfraglen, 		//maxfraglen IP片段最大尺寸
		fragheaderlen;		//fragheaderlen 是报头尺寸 
	int csummode = CHECKSUM_NONE;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue)) {			//如果是第一个IP片段
		/*
		 * setup for corking.
		 */
		opt = ipc->opt;
		if (opt) {
			if (inet->cork.opt == NULL) {
				inet->cork.opt = kmalloc(sizeof(struct ip_options) + 40, sk->sk_allocation);		//optlen 最大40 bytes
				if (unlikely(inet->cork.opt == NULL))
					return -ENOBUFS;
			}
			memcpy(inet->cork.opt, opt, sizeof(struct ip_options)+opt->optlen);		//ip_options 指出每个选项是否存在, 偏移量
			inet->cork.flags |= IPCORK_OPT;		//如果有opt则标记
			inet->cork.addr = ipc->addr;		//cork.addr 是什么
		}
		dst_hold(&rt->u.dst);
		inet->cork.fragsize = mtu = dst_pmtu(&rt->u.dst);		//路径mtu
		inet->cork.rt = rt;		//用于传输此IP数据段的路由表缓存项
		inet->cork.length = 0;
		sk->sk_sndmsg_page = NULL;
		sk->sk_sndmsg_off = 0;
		if ((exthdrlen = rt->u.dst.header_len) != 0) {			//header_len 返回主缓冲区中的数据量
			length += exthdrlen;
			transhdrlen += exthdrlen;			//	transhdrlen: 传输报头len(TCP/UDP/ICMP报头)
		}
	} else {
		rt = inet->cork.rt;
		if (inet->cork.flags & IPCORK_OPT)
			opt = inet->cork.opt;

		transhdrlen = 0;			//transhdrlen ！= 0 表示工作在第一个片段				transhdrlen == 0 表示未工作在第一片段
		exthdrlen = 0;
		mtu = inet->cork.fragsize;
	}
	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;		//8字节对齐

	if (inet->cork.length + length > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu-exthdrlen);
		return -EMSGSIZE;
	}

	/*
	 * transhdrlen > 0 means that this is the first fragment and we wish
	 * it won't be fragmented in the future.
	 */
	if (transhdrlen &&
	    length + fragheaderlen <= mtu &&
	    rt->u.dst.dev->features&(NETIF_F_IP_CSUM|NETIF_F_NO_CSUM|NETIF_F_HW_CSUM) &&
	    !exthdrlen)
		csummode = CHECKSUM_HW;

	inet->cork.length += length;

	/* So, what's going on in the loop below?
	 *
	 * We use calculated fragment length to generate chained skb,
	 * each of segments is IP fragment ready for sending to network after
	 * adding appropriate IP header.
	 */

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)		//当队列为空时就强制分配
		goto alloc_new_skb;

	while (length > 0) {		//length代表剩余要传输的数据量
		/* Check if the remaining data fits into current packet. */
		copy = mtu - skb->len;
		if (copy < length)
			copy = maxfraglen - skb->len;		//copy初始化为当前ip片段所剩空间
		if (copy <= 0) {		//需要另外一个片段
			char *data;
			unsigned int datalen;		//要拷贝到缓冲区的数据量
			unsigned int fraglen;		//片段能容纳最大数据量
			unsigned int fraggap;		//缓冲区间隔(8字节对齐)
			unsigned int alloclen;
			struct sk_buff *skb_prev;
alloc_new_skb:
			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			/*
			 * If remaining data exceeds the mtu,
			 * we know we need more fragment(s).
			 */
			datalen = length + fraggap;		//length = L4数据 + L4报头 + 外部报头
			if (datalen > mtu - fragheaderlen)		//一个片段装不下
				datalen = maxfraglen - fragheaderlen;
			fraglen = datalen + fragheaderlen;		//fraglen <= mtu, 有可能填不满

			if ((flags & MSG_MORE) && 
			    !(rt->u.dst.dev->features&NETIF_F_SG))	//如果后续有报文, 且不支持分散/聚集io, 缓冲区分配mtu大小
				alloclen = mtu;
			else
				alloclen = datalen + fragheaderlen;		//否则分配够用的大小即可

			/* The last fragment gets additional space at tail.
			 * Note, with MSG_MORE we overallocate on fragments,
			 * because we have no idea what fragment will be
			 * the last.
			 */
			if (datalen == length)
				alloclen += rt->u.dst.trailer_len;

			if (transhdrlen) {		//如果是首包
				skb = sock_alloc_send_skb(sk, 
						alloclen + hh_len + 15,
						(flags & MSG_DONTWAIT), &err);
			} else {
				skb = NULL;
				if (atomic_read(&sk->sk_wmem_alloc) <=
				    2 * sk->sk_sndbuf)
					skb = sock_wmalloc(sk, 
							   alloclen + hh_len + 15, 1,
							   sk->sk_allocation);
				if (unlikely(skb == NULL))
					err = -ENOBUFS;
			}
			if (skb == NULL)
				goto error;

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = csummode;		//指出出口设备是否提供L4硬件校验功能
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fraglen);
			skb->nh.raw = data + exthdrlen;
			data += fragheaderlen;
			skb->h.raw = data + exthdrlen;		//h.raw指向ip报头与extra报头之后的位置

			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data + transhdrlen, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				data += fraggap;
				skb_trim(skb_prev, maxfraglen);
			}

			copy = datalen - transhdrlen - fraggap;
			if (copy > 0 && getfrag(from, data + transhdrlen, offset, copy, fraggap, skb) < 0) {
				err = -EFAULT;
				kfree_skb(skb);
				goto error;
			}

			offset += copy;
			length -= datalen - fraggap;
			transhdrlen = 0;
			exthdrlen = 0;
			csummode = CHECKSUM_NONE;

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		if (copy > length)
			copy = length;

		if (!(rt->u.dst.dev->features&NETIF_F_SG)) {
			unsigned int off;

			off = skb->len;
			if (getfrag(from, skb_put(skb, copy), 
					offset, copy, off, skb) < 0) {
				__skb_trim(skb, off);
				err = -EFAULT;
				goto error;
			}
		} else {
			int i = skb_shinfo(skb)->nr_frags;
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i-1];
			struct page *page = sk->sk_sndmsg_page;
			int off = sk->sk_sndmsg_off;
			unsigned int left;

			if (page && (left = PAGE_SIZE - off) > 0) {
				if (copy >= left)
					copy = left;
				if (page != frag->page) {
					if (i == MAX_SKB_FRAGS) {
						err = -EMSGSIZE;
						goto error;
					}
					get_page(page);
	 				skb_fill_page_desc(skb, i, page, sk->sk_sndmsg_off, 0);
					frag = &skb_shinfo(skb)->frags[i];
				}
			} else if (i < MAX_SKB_FRAGS) {
				if (copy > PAGE_SIZE)
					copy = PAGE_SIZE;
				page = alloc_pages(sk->sk_allocation, 0);
				if (page == NULL)  {
					err = -ENOMEM;
					goto error;
				}
				sk->sk_sndmsg_page = page;
				sk->sk_sndmsg_off = 0;

				skb_fill_page_desc(skb, i, page, 0, 0);
				frag = &skb_shinfo(skb)->frags[i];
				skb->truesize += PAGE_SIZE;
				atomic_add(PAGE_SIZE, &sk->sk_wmem_alloc);
			} else {
				err = -EMSGSIZE;
				goto error;
			}
			if (getfrag(from, page_address(frag->page)+frag->page_offset+frag->size, offset, copy, skb->len, skb) < 0) {
				err = -EFAULT;
				goto error;
			}
			sk->sk_sndmsg_off += copy;
			frag->size += copy;
			skb->len += copy;
			skb->data_len += copy;
		}
		offset += copy;
		length -= copy;
	}

	return 0;

error:
	inet->cork.length -= length;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err; 
}

ssize_t	ip_append_page(struct sock *sk, struct page *page,
		       int offset, size_t size, int flags)
{
	struct inet_opt *inet = inet_sk(sk);
	struct sk_buff *skb;
	struct rtable *rt;
	struct ip_options *opt = NULL;
	int hh_len;
	int mtu;
	int len;
	int err;
	unsigned int maxfraglen, fragheaderlen, fraggap;

	if (inet->hdrincl)
		return -EPERM;

	if (flags&MSG_PROBE)
		return 0;

	if (skb_queue_empty(&sk->sk_write_queue))
		return -EINVAL;

	rt = inet->cork.rt;
	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (!(rt->u.dst.dev->features&NETIF_F_SG))
		return -EOPNOTSUPP;

	hh_len = LL_RESERVED_SPACE(rt->u.dst.dev);
	mtu = inet->cork.fragsize;

	fragheaderlen = sizeof(struct iphdr) + (opt ? opt->optlen : 0);
	maxfraglen = ((mtu - fragheaderlen) & ~7) + fragheaderlen;

	if (inet->cork.length + size > 0xFFFF - fragheaderlen) {
		ip_local_error(sk, EMSGSIZE, rt->rt_dst, inet->dport, mtu);
		return -EMSGSIZE;
	}

	if ((skb = skb_peek_tail(&sk->sk_write_queue)) == NULL)
		return -EINVAL;

	inet->cork.length += size;

	while (size > 0) {
		int i;

		/* Check if the remaining data fits into current packet. */
		len = mtu - skb->len;
		if (len < size)
			len = maxfraglen - skb->len;
		if (len <= 0) {
			struct sk_buff *skb_prev;
			char *data;
			struct iphdr *iph;
			int alloclen;

			skb_prev = skb;
			if (skb_prev)
				fraggap = skb_prev->len - maxfraglen;
			else
				fraggap = 0;

			alloclen = fragheaderlen + hh_len + fraggap + 15;
			skb = sock_wmalloc(sk, alloclen, 1, sk->sk_allocation);
			if (unlikely(!skb)) {
				err = -ENOBUFS;
				goto error;
			}

			/*
			 *	Fill in the control structures
			 */
			skb->ip_summed = CHECKSUM_NONE;
			skb->csum = 0;
			skb_reserve(skb, hh_len);

			/*
			 *	Find where to start putting bytes.
			 */
			data = skb_put(skb, fragheaderlen + fraggap);
			skb->nh.iph = iph = (struct iphdr *)data;
			data += fragheaderlen;
			skb->h.raw = data;

			if (fraggap) {
				skb->csum = skb_copy_and_csum_bits(
					skb_prev, maxfraglen,
					data, fraggap, 0);
				skb_prev->csum = csum_sub(skb_prev->csum,
							  skb->csum);
				skb_trim(skb_prev, maxfraglen);
			}

			/*
			 * Put the packet on the pending queue.
			 */
			__skb_queue_tail(&sk->sk_write_queue, skb);
			continue;
		}

		i = skb_shinfo(skb)->nr_frags;
		if (len > size)
			len = size;
		if (skb_can_coalesce(skb, i, page, offset)) {
			skb_shinfo(skb)->frags[i-1].size += len;
		} else if (i < MAX_SKB_FRAGS) {
			get_page(page);
			skb_fill_page_desc(skb, i, page, offset, len);
		} else {
			err = -EMSGSIZE;
			goto error;
		}

		if (skb->ip_summed == CHECKSUM_NONE) {
			unsigned int csum;
			csum = csum_page(page, offset, len);
			skb->csum = csum_block_add(skb->csum, csum, skb->len);
		}

		skb->len += len;
		skb->data_len += len;
		offset += len;
		size -= len;
	}
	return 0;

error:
	inet->cork.length -= size;
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	return err;
}

/*
 *	Combined all pending IP fragments on the socket as one IP datagram
 *	and push them out.
 */
int ip_push_pending_frames(struct sock *sk)
{
	struct sk_buff *skb, *tmp_skb;
	struct sk_buff **tail_skb;
	struct inet_opt *inet = inet_sk(sk);
	struct ip_options *opt = NULL;
	struct rtable *rt = inet->cork.rt;
	struct iphdr *iph;
	int df = 0;
	__u8 ttl;
	int err = 0;

	if ((skb = __skb_dequeue(&sk->sk_write_queue)) == NULL)
		goto out;
	tail_skb = &(skb_shinfo(skb)->frag_list);

	/* move skb->data to ip header from ext header */
	if (skb->data < skb->nh.raw)
		__skb_pull(skb, skb->nh.raw - skb->data);
	while ((tmp_skb = __skb_dequeue(&sk->sk_write_queue)) != NULL) {
		__skb_pull(tmp_skb, skb->h.raw - skb->nh.raw);
		*tail_skb = tmp_skb;
		tail_skb = &(tmp_skb->next);
		skb->len += tmp_skb->len;
		skb->data_len += tmp_skb->len;
		skb->truesize += tmp_skb->truesize;
		__sock_put(tmp_skb->sk);
		tmp_skb->destructor = NULL;
		tmp_skb->sk = NULL;
	}

	/* Unless user demanded real pmtu discovery (IP_PMTUDISC_DO), we allow
	 * to fragment the frame generated here. No matter, what transforms
	 * how transforms change size of the packet, it will come out.
	 */
	if (inet->pmtudisc != IP_PMTUDISC_DO)
		skb->local_df = 1;

	/* DF bit is set when we want to see DF on outgoing frames.
	 * If local_df is set too, we still allow to fragment this frame
	 * locally. */
	if (inet->pmtudisc == IP_PMTUDISC_DO ||
	    (!skb_shinfo(skb)->frag_list && ip_dont_fragment(sk, &rt->u.dst)))
		df = htons(IP_DF);

	if (inet->cork.flags & IPCORK_OPT)
		opt = inet->cork.opt;

	if (rt->rt_type == RTN_MULTICAST)
		ttl = inet->mc_ttl;
	else
		ttl = ip_select_ttl(inet, &rt->u.dst);

	iph = (struct iphdr *)skb->data;
	iph->version = 4;
	iph->ihl = 5;
	if (opt) {
		iph->ihl += opt->optlen>>2;
		ip_options_build(skb, opt, inet->cork.addr, rt, 0);
	}
	iph->tos = inet->tos;
	iph->tot_len = htons(skb->len);
	iph->frag_off = df;
	if (!df) {
		__ip_select_ident(iph, &rt->u.dst, 0);
	} else {
		iph->id = htons(inet->id++);
	}
	iph->ttl = ttl;
	iph->protocol = sk->sk_protocol;
	iph->saddr = rt->rt_src;
	iph->daddr = rt->rt_dst;
	ip_send_check(iph);

	skb->priority = sk->sk_priority;
	skb->dst = dst_clone(&rt->u.dst);

	/* Netfilter gets whole the not fragmented skb. */
	err = NF_HOOK(PF_INET, NF_IP_LOCAL_OUT, skb, NULL, 
		      skb->dst->dev, dst_output);
	if (err) {
		if (err > 0)
			err = inet->recverr ? net_xmit_errno(err) : 0;
		if (err)
			goto error;
	}

out:
	inet->cork.flags &= ~IPCORK_OPT;
	if (inet->cork.opt) {
		kfree(inet->cork.opt);
		inet->cork.opt = NULL;
	}
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
	return err;

error:
	IP_INC_STATS(IPSTATS_MIB_OUTDISCARDS);
	goto out;
}

/*
 *	Throw away all pending data on the socket.
 */
void ip_flush_pending_frames(struct sock *sk)
{
	struct inet_opt *inet = inet_sk(sk);
	struct sk_buff *skb;

	while ((skb = __skb_dequeue_tail(&sk->sk_write_queue)) != NULL)
		kfree_skb(skb);

	inet->cork.flags &= ~IPCORK_OPT;
	if (inet->cork.opt) {
		kfree(inet->cork.opt);
		inet->cork.opt = NULL;
	}
	if (inet->cork.rt) {
		ip_rt_put(inet->cork.rt);
		inet->cork.rt = NULL;
	}
}


/*
 *	Fetch data from kernel space and fill in checksum if needed.
 */
static int ip_reply_glue_bits(void *dptr, char *to, int offset, 
			      int len, int odd, struct sk_buff *skb)
{
	unsigned int csum;

	csum = csum_partial_copy_nocheck(dptr+offset, to, len, 0);
	skb->csum = csum_block_add(skb->csum, csum, odd);
	return 0;  
}

/* 
 *	Generic function to send a packet as reply to another packet.
 *	Used to send TCP resets so far. ICMP should use this function too.
 *
 *	Should run single threaded per socket because it uses the sock 
 *     	structure to pass arguments.
 *
 *	LATER: switch from ip_build_xmit to ip_append_*
 */
void ip_send_reply(struct sock *sk, struct sk_buff *skb, struct ip_reply_arg *arg,
		   unsigned int len)
{
	struct inet_opt *inet = inet_sk(sk);
	struct {
		struct ip_options	opt;
		char			data[40];
	} replyopts;
	struct ipcm_cookie ipc;
	u32 daddr;
	struct rtable *rt = (struct rtable*)skb->dst;

	if (ip_options_echo(&replyopts.opt, skb))
		return;

	daddr = ipc.addr = rt->rt_src;
	ipc.opt = NULL;

	if (replyopts.opt.optlen) {
		ipc.opt = &replyopts.opt;

		if (ipc.opt->srr)
			daddr = replyopts.opt.faddr;
	}

	{
		struct flowi fl = { .nl_u = { .ip4_u =
					      { .daddr = daddr,
						.saddr = rt->rt_spec_dst,
						.tos = RT_TOS(skb->nh.iph->tos) } },
				    /* Not quite clean, but right. */
				    .uli_u = { .ports =
					       { .sport = skb->h.th->dest,
					         .dport = skb->h.th->source } },
				    .proto = sk->sk_protocol };
		if (ip_route_output_key(&rt, &fl))
			return;
	}

	/* And let IP do all the hard work.

	   This chunk is not reenterable, hence spinlock.
	   Note that it uses the fact, that this function is called
	   with locally disabled BH and that sk cannot be already spinlocked.
	 */
	bh_lock_sock(sk);
	inet->tos = skb->nh.iph->tos;
	sk->sk_priority = skb->priority;
	sk->sk_protocol = skb->nh.iph->protocol;
	ip_append_data(sk, ip_reply_glue_bits, arg->iov->iov_base, len, 0,
		       &ipc, rt, MSG_DONTWAIT);
	if ((skb = skb_peek(&sk->sk_write_queue)) != NULL) {
		if (arg->csumoffset >= 0)
			*((u16 *)skb->h.raw + arg->csumoffset) = csum_fold(csum_add(skb->csum, arg->csum));
		skb->ip_summed = CHECKSUM_NONE;
		ip_push_pending_frames(sk);
	}

	bh_unlock_sock(sk);

	ip_rt_put(rt);
}

/*
 *	IP protocol layer initialiser
 */

static struct packet_type ip_packet_type = {
	.type = __constant_htons(ETH_P_IP),
	.func = ip_rcv,
};

/*
 *	IP registers the packet type and then calls the subprotocol initialisers
 */

void __init ip_init(void)
{
	dev_add_pack(&ip_packet_type);

	ip_rt_init();
	inet_initpeers();

#if defined(CONFIG_IP_MULTICAST) && defined(CONFIG_PROC_FS)
	igmp_mc_proc_init();
#endif
}

EXPORT_SYMBOL(ip_finish_output);
EXPORT_SYMBOL(ip_fragment);
EXPORT_SYMBOL(ip_generic_getfrag);
EXPORT_SYMBOL(ip_queue_xmit);
EXPORT_SYMBOL(ip_send_check);

#ifdef CONFIG_SYSCTL
EXPORT_SYMBOL(sysctl_ip_default_ttl);
#endif
