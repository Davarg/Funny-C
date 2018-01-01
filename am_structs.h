#ifndef AM_STRUCTS_H
#define AM_STRUCTS_H

#define AM_ETHER_ADDR_LEN 6
#define AM_ETHER_HDR_LEN 14

struct amEtherHdr {
  unsigned char etherDstAddr[AM_ETHER_ADDR_LEN];
  unsigned char etherSrcAddr[AM_ETHER_ADDR_LEN];
  unsigned short etherType;
};

struct amIPHdr {
  unsigned char ipVersionAndHeaderLength;
  unsigned char ipTOS;
  unsigned short ipLength;
  unsigned short ipID;
  unsigned short ipFragmentOffsetAndFlags;
  unsigned char ipTTL;
  unsigned char ipType;
  unsigned short ipChecksum;
  unsigned int ipSrcAddr;
  unsigned int ipDstAddr;
};

struct amTCPHdr {
  unsigned short tcpSrcPort;
  unsigned short tcpDstPort;
  unsigned int tcpSeq;
  unsigned int tcpAck;
  unsigned char tcpReserved:4;
  unsigned char tcpOffset:4;

  unsigned char tcpFlags;
  #define TCP_FIN 0x01
  #define TCP_SYN 0x02
  #define TCP_RST 0x04
  #define TCP_PUSH 0x08
  #define TCP_ACK 0x10
  #define TCP_URG 0x20

  unsigned short tcp_window;
  unsigned short tcpChecksum;
  unsigned short tcpUrgent;
};

#endif
