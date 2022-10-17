#pragma once
#include <ndis.h>
#include "filter.h"
#define ETHERTYPE_IP 0x0800

/* Internal time */
#define SCAN_INTERVAL   (-1*10*1000*10*2)

/* UDP port numbers for DHCP */
#define	DHCP_SERVER_PORT	67	/* from client to server */
#define DHCP_CLIENT_PORT	68	/* from server to client */

/* DHCP message OP code */
#define DHCP_BOOTREQUEST	1
#define DHCP_BOOTREPLY		2

/* DHCP message type */
#define	DHCP_DISCOVER		1
#define DHCP_OFFER		2
#define	DHCP_REQUEST		3
#define	DHCP_DECLINE		4
#define	DHCP_ACK		5
#define DHCP_NAK		6
#define	DHCP_RELEASE		7
#define DHCP_INFORM		8

/* DHCP RETRANSMISSION TIMEOUT (microseconds) */
#define DHCP_INITIAL_RTO	(4*1000000)
#define DHCP_MAX_RTO		(64*1000000)

/* Some basic constants */
#define IPPACKET_SIZE		1500
#define MAGIC_COOKIE		0x63825363
#define BROADCAST_FLAG		0x8000
#define MAC_BCAST_ADDR		"\xff\xff\xff\xff\xff\xff"
#define ETH_ALEN 6 

typedef unsigned char UCHAR;
typedef unsigned short USHORT;
typedef unsigned long ULONG;
typedef char* PCHAR;
typedef unsigned short WCHAR;

typedef  struct _dhcpmsg
{
    UCHAR        op;
    UCHAR        htype;
    UCHAR        hlen;
    UCHAR        hops;
    ULONG       xid;
    USHORT       secs;
    USHORT       flags;
    ULONG       ciaddr;
    ULONG       yiaddr;
    ULONG       siaddr;
    ULONG       giaddr;
    UCHAR        chaddr[16];
    UCHAR        sname[64];
    UCHAR        file[128];
    UCHAR        options[312];
} dhcpmsg,*pdhcpmsg;

typedef  struct _dhcpoption
{
    UCHAR        code;
    UCHAR        len;
    UCHAR        data[256];
} dhcpoption;

typedef struct _packed_ether_header {
    UCHAR  ether_dhost[ETH_ALEN];      /* destination eth addr */
    UCHAR  ether_shost[ETH_ALEN];      /* source ether addr    */
    USHORT ether_type;                 /* packet type ID field */
} packed_ether_header;

typedef struct _udpipMessage
{
    struct _packed_ether_header	ethhdr;
    UCHAR	udpipmsg[IPPACKET_SIZE];
} udpipMessage;
/*
 * Structure of an internet header, naked of options.
 */
typedef struct _ipheader
{
    UCHAR	ip_hl : 4;				/* header length 4bits */
    UCHAR	ip_v : 4;                /* version 4bits */
    UCHAR	ip_tos;                /* type of service */
    USHORT	ip_len;                 /* total length */
    USHORT	ip_id;                  /* identification */
    USHORT	ip_off;                 /* fragment offset field */
    UCHAR	ip_ttl;                 /* time to live */
    UCHAR	ip_p;                   /* protocol */
    USHORT	ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst;  /* source and dest address */
} ipheader;
typedef struct _udpheader
{
    USHORT udp_sport;			/* source port */
    USHORT udp_dport;			/* destination port */
    USHORT udp_length;		/* udp packet total length (include the udp header) */
    USHORT udp_sum;		/* udp packet checksum */
}udpheader;


/* DHCP option and value (cf. RFC1533) */
enum
{
    padOption = 0,
    subnetMask = 1,
    timerOffset = 2,
    routersOnSubnet = 3,
    timeServer = 4,
    nameServer = 5,
    dns = 6,
    logServer = 7,
    cookieServer = 8,
    lprServer = 9,
    impressServer = 10,
    resourceLocationServer = 11,
    hostName = 12,
    bootFileSize = 13,
    meritDumpFile = 14,
    domainName = 15,
    swapServer = 16,
    rootPath = 17,
    extentionsPath = 18,
    IPforwarding = 19,
    nonLocalSourceRouting = 20,
    policyFilter = 21,
    maxDgramReasmSize = 22,
    defaultIPTTL = 23,
    pathMTUagingTimeout = 24,
    pathMTUplateauTable = 25,
    ifMTU = 26,
    allSubnetsLocal = 27,
    broadcastAddr = 28,
    performMaskDiscovery = 29,
    maskSupplier = 30,
    performRouterDiscovery = 31,
    routerSolicitationAddr = 32,
    staticRoute = 33,
    trailerEncapsulation = 34,
    arpCacheTimeout = 35,
    ethernetEncapsulation = 36,
    tcpDefaultTTL = 37,
    tcpKeepaliveInterval = 38,
    tcpKeepaliveGarbage = 39,
    nisDomainName = 40,
    nisServers = 41,
    ntpServers = 42,
    vendorSpecificInfo = 43,
    netBIOSnameServer = 44,
    netBIOSdgramDistServer = 45,
    netBIOSnodeType = 46,
    netBIOSscope = 47,
    xFontServer = 48,
    xDisplayManager = 49,
    dhcpRequestedIPaddr = 50,
    dhcpIPaddrLeaseTime = 51,
    dhcpOptionOverload = 52,
    dhcpMessageType = 53,
    dhcpServerIdentifier = 54,
    dhcpParamRequest = 55,
    dhcpMsg = 56,
    dhcpMaxMsgSize = 57,
    dhcpT1value = 58,
    dhcpT2value = 59,
    dhcpClassIdentifier = 60,
    dhcpClientIdentifier = 61,
    endOption = 255
};

void sendNDISPacket(PMS_FILTER pFilter);
