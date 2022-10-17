#include "precomp.h"
#include "dhcpPacket.h"

ULONG
ntohl(ULONG netlong)//从网络字节顺序转换为主机字节顺序
{
	//t << "fdsfsa";
	UCHAR hostlong[4];
	PCHAR pnetlong = (PCHAR)&netlong;
	hostlong[0] = pnetlong[3];
	hostlong[1] = pnetlong[2];
	hostlong[2] = pnetlong[1];
	hostlong[3] = pnetlong[0];
	return *(ULONG*)hostlong;
}

// network order to host order for short
USHORT
ntohs(USHORT netshort)
{
	UCHAR hostshort[4];
	PCHAR pnetshort = (PCHAR)&netshort;
	hostshort[0] = pnetshort[1];
	hostshort[1] = pnetshort[0];
	return *(USHORT*)hostshort;
}

// calc the check sum of the given data 
USHORT in_cksum(USHORT* addr, int len)
{
	register int sum = 0;
	register USHORT* w = addr;
	register int nleft = len;
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}
	if (nleft == 1)
	{
		UCHAR a = 0;
		RtlCopyMemory(&a, w, 1);
		sum += a;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}


int buildDhcpDiscover(ULONG  in_xid, UCHAR* in_pchaddr, dhcpmsg* inout_udpmsg)
{
	KdPrint(("build Dhcp Packet"));
	//DbgPrint("buildDhcpDiscover Enter");
	int length = 0;
	/* client hardware */
	KdBreakPoint();
	RtlCopyMemory(inout_udpmsg->chaddr, in_pchaddr, 6);
	/* client ip address */
	/* client file info */
	/* client flags info */
	inout_udpmsg->flags = ntohs(BROADCAST_FLAG);
	/* client gateway ip info */
	/* client hardware address length */
	inout_udpmsg->hlen = ETH_ALEN;
	/* client hop counts */
	inout_udpmsg->hops = '\x0';
	/*
	client hardware type
	ethernet = 1
	*/
	inout_udpmsg->htype = '\x01';
	/*
	client opcode
	boot request = 1
	boot reply = 2
	*/
	inout_udpmsg->op = DHCP_BOOTREQUEST;
	/* client seconds eslapsed */
	inout_udpmsg->secs = 0;
	/* server ip address*/
	/* server host name info*/
	/* client xid */
	inout_udpmsg->xid = in_xid;
	/* your ip address*/

	/*
	 In the following part, we will build the options.
	*/
	// get a pointer to the option parts of the dhcp packet
	unsigned char* p1 = (unsigned char*)(inout_udpmsg->options);
	//*reinterpret_cast<unsigned long*>(p) = ntohl(MAGIC_COOKIE);
	*p1 = (ULONG)ntohl(MAGIC_COOKIE);
	ULONG* p = (ULONG*)p1;
	p += 4;
	/*
	build the DHCP message type
	option 53
	length 1
	data DHCP_DISCOVER
	*/
	*(p++) = dhcpMessageType;
	*(p++) = 1;
	*(p++) = DHCP_DISCOVER;
	/*
	build option 55
	*/
	*(p++) = dhcpParamRequest;
	*(p++) = 0x24;
	*(p++) = 0x01;
	*(p++) = 0x02;
	*(p++) = 0x03;
	*(p++) = 0x04;
	*(p++) = 0x05;
	*(p++) = 0x06;
	*(p++) = 0x0B;
	*(p++) = 0x0C;
	*(p++) = 0x0D;
	*(p++) = 0x0F;
	*(p++) = 0x10;
	*(p++) = 0x11;
	*(p++) = 0x12;
	*(p++) = 0x16;
	*(p++) = 0x17;
	*(p++) = 0x1C;
	*(p++) = 0x28;
	*(p++) = 0x29;
	*(p++) = 0x2A;
	*(p++) = 0x2B;
	*(p++) = 0x32;
	*(p++) = 0x33;
	*(p++) = 0x36;
	*(p++) = 0x3A;
	*(p++) = 0x3B;
	*(p++) = 0x3C;
	*(p++) = 0x42;
	*(p++) = 0x43;
	*(p++) = 0x80;
	*(p++) = 0x81;
	*(p++) = 0x82;
	*(p++) = 0x83;
	*(p++) = 0x84;
	*(p++) = 0x85;
	*(p++) = 0x86;
	*(p++) = 0x87;
	/*
	build option 57 DHCP Maximum Message Size
	*/
	*(p++) = dhcpMaxMsgSize;
	*(p++) = 2;
	*(p++) = 0x04;
	*(p++) = 0xEC;
	/*
	build option 97 UUID/GUID-based Client Identifiers
	*/
	*(p++) = 97;
	*(p++) = 17;
	*(p++) = 0x00;
	*(p++) = 0xF0;
	*(p++) = 0xF8;
	*(p++) = 0x8A;
	*(p++) = 0x91;
	*(p++) = 0x95;
	*(p++) = 0x42;
	*(p++) = 0x11;
	*(p++) = 0xD8;
	*(p++) = 0xAE;
	*(p++) = 0x1D;
	*(p++) = 0x00;
	*(p++) = 0x30;
	*(p++) = 0xD3;
	*(p++) = 0x00;
	*(p++) = 0x1E;
	*(p++) = 0x25;
	/*
	build option 93	Client system architecture
	*/
	*(p++) = 93;
	*(p++) = 2;
	*(p++) = 0;
	*(p++) = 0;
	/*
	build option 94 Client network device interface
	*/
	*(p++) = 94;
	*(p++) = 3;
	*(p++) = 1;
	*(p++) = 2;
	*(p++) = 1;
	/*
	build option 60 PXEClient
	*/
	*(p++) = dhcpClassIdentifier;
	*(p++) = 33;//9+1+4+1+5+1+4+1+6+1;
	strcpy((char*)p, "PXEClient:Arch:00000:UNDI:002001");
	p += 33;
	/*
	end option
	*/
	*(p++) = endOption;
	length = p - (PUCHAR)inout_udpmsg;
	//t << "buildDhcpDiscover Exit";
	//DbgPrint("buildDhcpDiscover Exit");
	return sizeof(dhcpmsg);//length;
}

int buildMacPacket(UCHAR* in_udpmsg, int in_udplen, udpipMessage* inout_macmsg)
{
	//t << "buildMacPacket Enter";
	KdPrint(("build mac packet!"));
	int length = 0;

	// set the destination mac address
	RtlCopyMemory(inout_macmsg->ethhdr.ether_dhost, MAC_BCAST_ADDR, 6);
	dhcpmsg* msg = (dhcpmsg*)in_udpmsg;

	// set the source mac address
	RtlCopyMemory(inout_macmsg->ethhdr.ether_shost, msg->chaddr, 6);

	// set the mac frame to ip type
	inout_macmsg->ethhdr.ether_type = ntohs(ETHERTYPE_IP);

	// get the pointer to ipheader and udpheader
	ipheader* pipheader = (ipheader*)inout_macmsg->udpipmsg;
	udpheader* pudpheader = (udpheader*)(inout_macmsg->udpipmsg + sizeof(ipheader));

	// build the ipheader
	pipheader->ip_v = 4;		/* version=4 */
	pipheader->ip_hl = 5;		/* header length=5*4=20 */
	pipheader->ip_tos = 0x00;	/* type of servic default */
	pipheader->ip_len = ntohs(sizeof(ipheader) + sizeof(udpheader) + in_udplen);
	pipheader->ip_id = ntohs(0x00);	/* identification */
	pipheader->ip_off = ntohs(0x00);	/* no fragments */
	pipheader->ip_ttl = 0x80;	/* ttl=128 */
	pipheader->ip_p = 0x11;		/* protocol=UDP */
	pipheader->ip_sum = in_cksum((USHORT*)pipheader, sizeof(ipheader));	/* we don't calculate the checksum .Updated on 040930, checksum needn't reverse to network order*/
	pipheader->ip_src.S_un.S_addr = ntohl(0x00L); /* no ip address yet */
	pipheader->ip_dst.S_un.S_addr = ntohl(0x0ffffffffL);/* broadcast address */

	// build the udpheader
	pudpheader->udp_dport = ntohs(DHCP_SERVER_PORT); /* destination is the dhcp server */
	pudpheader->udp_sport = ntohs(DHCP_CLIENT_PORT); /* source is the dhcp client */
	pudpheader->udp_length = ntohs(sizeof(udpheader) + in_udplen); /* udp total length (include the udp header) */
	pudpheader->udp_sum = ntohs(0x00);

	// copy the dhcp or udp data part to mac frame
	RtlCopyMemory((inout_macmsg->udpipmsg + sizeof(ipheader) + sizeof(udpheader)), in_udpmsg, in_udplen);
	length = sizeof(packed_ether_header) + sizeof(ipheader) + sizeof(udpheader) + in_udplen;

	//t << "buildMacPacket Exit";
	return length;
}

void sendNDISPacket(PMS_FILTER pFilter) {
	UCHAR		MacAddress[6] = { 0,0,0,1 };
	//PNDIS_PACKET pPacket = NULL;
	udpipMessage testUdpPacket;
	dhcpmsg testdhcpmsg;
	RtlZeroMemory(&testUdpPacket, sizeof(testUdpPacket));
	RtlZeroMemory(&testdhcpmsg, sizeof(testdhcpmsg));
	int dhcpDataLength = buildDhcpDiscover(0x1L, MacAddress, &testdhcpmsg);
	int dhcpMacLength = buildMacPacket((PUCHAR)&testdhcpmsg, dhcpDataLength, &testUdpPacket);

	PNET_BUFFER_LIST pSendNetBufferList = NdisAllocateNetBufferAndNetBufferList(pFilter->UserSendNetPacketPool, 0, 0, NULL, 0, 0);
	//申请失败直接结束   
	if (pSendNetBufferList == NULL)
	{
		return;
	}
	//这部很重要
	pSendNetBufferList->SourceHandle = pFilter->FilterHandle;
	PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(pSendNetBufferList);
	NET_BUFFER_LIST_NEXT_NBL(pSendNetBufferList) = NULL;
	NdisRetreatNetBufferDataStart(nb, dhcpMacLength, 0, NULL);
	UCHAR* dst = NdisGetDataBuffer(nb, dhcpMacLength, NULL, 1, 0);
	memcpy(dst, &testUdpPacket, dhcpMacLength);
	NdisFSendNetBufferLists(pFilter->FilterHandle, pSendNetBufferList, NDIS_DEFAULT_PORT_NUMBER, 0);
	KdBreakPoint();
	return 0;
}