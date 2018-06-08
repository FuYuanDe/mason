/**
 * Dinstar rtp relay
 * Copyright (C) 2013-2016
 * All rights reserved
 *
 * @file    xrtp_rtcp.h
 * @brief   
 *
 *
 * @author  kyle
 * @version 1.0
 * @date    2016-11-11
*/

#ifndef	_XRTP_RTCP_H_
#define	_XRTP_RTCP_H_


#pragma pack(1)

#ifndef U32
#define U32 __u32
#define U16 __u16
#define U8  __u8
#define S8  char
#endif

#define TRUE                    1
#if defined(__LITTLE_ENDIAN_BITFIELD)
#define CONDIF_LITTLE_ENDIAN    1
#define CONDIF_BIG_ENDIAN       0
#elif defined (__BIG_ENDIAN_BITFIELD)
#define CONDIF_LITTLE_ENDIAN    0
#define CONDIF_BIG_ENDIAN       1
#endif

  
typedef struct
{
	U32         ssrc;         /* SSRC of sender */
	U32         ntp_sec;      /* NTP timestamp, most significant word */
	U32         ntp_frac;     /* NTP timestamp, least significant word */
	U32         rtp_ts;       /* RTP timestamp */
	U32         sender_pcount;/* sender's packet count */
	U32         sender_bcount;/* sender's octet count */
} rtcp_sr;

typedef struct
{
	U32	ssrc;		    /* The ssrc to which this RR pertains */

	U8	fract_lost;     /* fraction lost*/
	U8	total_lost_h8;  /* cumulative number of packets lost */
	U16	total_lost_l16; /* cumulative number of packets lost */

	U32	last_seq;       /* extended highest sequence number received */
	U32	jitter;         /* interarrival jitter */
	U32	lsr;            /* last SR timestamp,in units of 1/65536 seconds*/
	U32	dlsr;           /* delay since last SR (32 middle bits of its NTP timestamp)*/
} rtcp_rr;

typedef struct
{
#if (CONDIF_BIG_ENDIAN == TRUE)
	U8  version:2;		/* RTP version            */
	U8  p:1;			/* padding flag           */
	U8  subtype:5;		/* application dependent  */
#elif (CONDIF_LITTLE_ENDIAN == TRUE)
	U8  subtype:5;		/* application dependent  */
	U8  p:1;			/* padding flag           */
	U8  version:2;		/* RTP version            */
#else
#error "please config endian mode"
#endif
	U8 pt;			/* packet type            */
	U16 length;			/* packet length          */
	U32 ssrc;
	S8 name[4];			/* four ASCII characters  */
	S8 data[1];			/* variable length field  */
} rtcp_app;


/* SDES packet types... */
typedef enum 
{
        RTCP_SDES_END   = 0,
        RTCP_SDES_CNAME = 1,
        RTCP_SDES_NAME  = 2,
        RTCP_SDES_EMAIL = 3,
        RTCP_SDES_PHONE = 4,
        RTCP_SDES_LOC   = 5,
        RTCP_SDES_TOOL  = 6,
        RTCP_SDES_NOTE  = 7,
        RTCP_SDES_PRIV  = 8
} rtcp_sdes_type;

typedef struct
{
	U8		type;		/* type of SDES item              */
	U8		length;		/* length of SDES item (in bytes) */
	S8		data[1];		/* text, not zero-terminated      */
} rtcp_sdes_item;


#define RTCP_SR   200
#define RTCP_RR   201
#define RTCP_SDES 202
#define RTCP_BYE  203
#define RTCP_APP  204

typedef struct
{
#if (CONDIF_BIG_ENDIAN == TRUE)
	U8 version:2;	/* packet type            */
	U8 p:1;			/* padding flag           */
	U8 count:5;		/* The number of reception report blocks */
	U8 pt;		/* payload type           */
#elif (CONDIF_LITTLE_ENDIAN == TRUE)
	U8 count:	5;	/* The number of reception report blocks */
	U8 p:1;			/* padding flag           */
	U8 version:2;	/* packet type            */
	U8 pt;		/* payload type           */
#else
#error "please config endian mode"
#endif
	U16 length;		/* packet length          */
}
rtcp_common;

typedef struct rtcphdr
{
	rtcp_common common;
	union
	{
		struct
		{
			rtcp_sr	sr;
			rtcp_rr rr[1];		/* variable-length list */
		}
		sr;
		struct
		{
			U32 ssrc;		/* source this RTCP packet is coming from */
			rtcp_rr rr[1];		/* variable-length list */
		}
		rr;
		struct rtcp_sdes_t
		{
			U32	ssrc;
			rtcp_sdes_item item[1];	/* list of SDES */
		}
		sdes;
		struct
		{
			U32 ssrc[1];	/* list of sources */
			/* can't express the trailing text... */
		}
		bye;
		struct
		{
			U32 ssrc;
			U8 name[4];
			U8 data[1];
		}
		app;
	} r;
}
rtcp_t;


typedef struct rtphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	U8		rtp_cc:4;
	U8		rtp_extbit:1;
	U8		rtp_padbit:1;
	U8		rtp_version:2;

	U8		rtp_paytype:7;
	U8		rtp_markbit:1;

#else
	U8		rtp_version:2;
	U8		rtp_padbit:1;
	U8		rtp_extbit:1;
	U8		rtp_cc:4;

	U8		rtp_markbit:1;
	U8		rtp_paytype:7;
#endif
	U16		rtp_seq_number;		/* xxx */
	U32		rtp_timestamp;		/* xxx */
	U32		rtp_ssrc;
} rtphdr_t;

#pragma pack()



#define RTP_MAX_PACKET_LEN		1500 


#endif
