/*
 * Copyright (c) 1982, 1986 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)if_ether.h	7.5 (Berkeley) 6/28/90
 *	$Id: if_ether.h,v 1.5 1994/05/17 22:31:02 jkh Exp $
 */

#ifndef _NETINET_IF_ETHER_H_
#define _NETINET_IF_ETHER_H_ 1

/*
 * Structure of a 10Mb/s Ethernet header.
 */
struct	ether_header {
	u_char	ether_dhost[6];
	u_char	ether_shost[6];
	u_short	ether_type;
};

#define	ETHERTYPE_PUP	0x0200		/* PUP protocol */
#define	ETHERTYPE_IP	0x0800		/* IP protocol */
#define ETHERTYPE_ARP	0x0806		/* Addr. resolution protocol */

/*
 * The ETHERTYPE_NTRAILER packet types starting at ETHERTYPE_TRAIL have
 * (type-ETHERTYPE_TRAIL)*512 bytes of data followed
 * by an ETHER type (as given above) and then the (variable-length) header.
 */
#define	ETHERTYPE_TRAIL		0x1000		/* Trailer packet */
#define	ETHERTYPE_NTRAILER	16

#define	ETHERMTU	1500
#define	ETHERMIN	(60-14)

#ifdef KERNEL
/*
 * Macro to map an IP multicast address to an Ethernet multicast address.
 * The high-order 25 bites of the Ethernet address are staticall assigned,
 * and the low-rder 23 bites are taken from the low end of the IP address.
 */
#define	ETHER_MAP_IP_MULTICAST(ipaddr, enaddr) \
	/* struct in_addr *ipaddr; */ \
	/* u_char enaddr[6]; */ \
{ \
	(enaddr)[0] = 0x01; \
	(enaddr)[1] = 0x00; \
	(enaddr)[2] = 0x5e; \
	(enaddr)[3] = ((u_char *)ipaddr)[1] & 0x7f; \
	(enaddr)[4] = ((u_char *)ipaddr)[2]; \
	(enaddr)[5] = ((u_char *)ipaddr)[3]; \
}
#endif

/*
 * Ethernet Address Resolution Protocol.
 *
 * See RFC 826 for protocol description.  Structure below is adapted
 * to resolving internet addresses.  Field names used correspond to 
 * RFC 826.
 */
struct	ether_arp {
	struct	arphdr ea_hdr;	/* fixed-size header */
	u_char	arp_sha[6];	/* sender hardware address */
	u_char	arp_spa[4];	/* sender protocol address */
	u_char	arp_tha[6];	/* target hardware address */
	u_char	arp_tpa[4];	/* target protocol address */
};
#define	arp_hrd	ea_hdr.ar_hrd
#define	arp_pro	ea_hdr.ar_pro
#define	arp_hln	ea_hdr.ar_hln
#define	arp_pln	ea_hdr.ar_pln
#define	arp_op	ea_hdr.ar_op


/*
 * Structure shared between the ethernet driver modules and
 * the address resolution code.  For example, each ec_softc or il_softc
 * begins with this structure.
 */
struct	arpcom {
	struct 	ifnet ac_if;		/* network-visible interface */
	u_char	ac_enaddr[6];		/* ethernet hardware address */
	struct in_addr ac_ipaddr;	/* copy of ip address- XXX */
	struct ether_multi *ac_multiaddrs; /* list of ether m'cast addrs */
	int	ac_multicnt;		/* length of ac_multiaddrs list */
};


/*
 * Internet to ethernet address resolution table.
 */
struct	arptab {
	struct	in_addr at_iaddr;	/* internet address */
	u_char	at_enaddr[6];		/* ethernet address */
	u_char	at_timer;		/* minutes since last reference */
	u_char	at_flags;		/* flags */
	struct	mbuf *at_hold;		/* last packet until resolved/timeout */
};

#ifdef	KERNEL
extern u_char	etherbroadcastaddr[6]; /* defined in net/if_ethersubr.c */
#if defined(ISO) && !defined(MULTICAST)
#define MULTICAST 1
#endif
#ifdef MULTICAST
u_char	ether_ipmulticast_min[6];
u_char	ether_ipmulticast_max[6];
#endif
struct	arptab *arptnew();

extern void ether_input(struct ifnet *, struct ether_header *, struct mbuf *);
extern char *ether_sprintf(u_char *);

#ifdef MULTICAST
/*    
 * Ethernet multicast address structure.  There is one of these for each
 * multicast address or range of multicast addresses that we are supposed
 * to listen to on a particular interface.  They are kept in a linked list,
 * rooted in the interface's arpcom structure.  (This really has nothing to
 * do with ARP, or with the Internet address family, but this appears to be
 * the minimally-disrupting place to put it.)
 */
struct ether_multi {
	u_char	enm_addrlo[6];		/* low or only address of range */
	u_char	enm_addrhi[6];		/* high or only address of range */
	struct arpcom *enm_ac;		/* back point to arpcom */
	u_int	enm_refcount;		/* no. claims to this addr/range */
	struct ether_multi *enm_next;	/* ptr to next ether_multi */
} ;

/*
 * Structure used by macros below to remember position when stepping through
 * all of the ether_multi records.
 */
struct ether_multistep {
      struct ether_multi  *e_enm;
};

/*
 * Macro for looking up the ether_multi record for a given range of Ethernet
 * multicast addresses connected to a given arpcom structure.  If no matching
 * record is found, "enm" returns NULL.
 */
#define ETHER_LOOKUP_MULTI(addrlo, addrhi, ac, enm) \
      /* u_char addrlo[6]; */ \
      /* u_char addrhi[6]; */ \
      /* struct arpcom *ac; */ \
      /* struct ether_multi *enm; */ \
{ \
      for ((enm) = (ac)->ac_multiaddrs; \
          (enm) != NULL && \
          (bcmp((enm)->enm_addrlo, (addrlo), 6) != 0 || \
           bcmp((enm)->enm_addrhi, (addrhi), 6) != 0); \
              (enm) = (enm)->enm_next); \
}

/*
 * Macro to step through all of the ether_multi records, one at a time.
 * The current position is remembered in "step", which the caller must
 * provide.  ETHER_FIRST_MULTI(), below, must be called to initialize "step"
 * and get the first record.  Both macros return a NULL "enm" when there
 * are no remaining records.
 */
#define ETHER_NEXT_MULTI(step, enm) \
      /* struct ether_multistep step; */  \
      /* struct ether_multi *enm; */  \
{ \
      if (((enm) = (step).e_enm) != NULL) \
              (step).e_enm = (enm)->enm_next; \
}

#define ETHER_FIRST_MULTI(step, ac, enm) \
      /* struct ether_multistep step; */ \
      /* struct arpcom *ac; */ \
      /* struct ether_multi *enm; */ \
{ \
      (step).e_enm = (ac)->ac_multiaddrs; \
      ETHER_NEXT_MULTI((step), (enm)); \
}
#endif /* _MULTICAST */
#endif /* KERNEL */
#endif /* _NETINET_IF_ETHER_H_ */
