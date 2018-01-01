#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdlib.h>

#include "am_structs.h"

/**
* MACROSES
*/
#define INTERFACE_KEY "-i"
#define SOURCE_IP_KEY "-sip"
#define SOURCE_MAC_KEY "-sm"
#define DESTINATION_IP_KEY "-dip"
#define DESTINATION_MAC_KEY "-dm"

#define kMaxIPLen 16
#define kMaxMacLen 17
#define kNeededArgsQty 10
#define kMaxInterfaceLen 16

/**
* FUNCTIONS
*/
void showTips(char *name);
void initGlobals(char *argv[]);
const uint8_t* getMac(u_char *macStr);

void decodeIP(const u_char *packet);
u_int decodeTCP(const u_char *packet);
void decodeEther(const u_char *packet);

void dump(const u_char *dataBuffer, const u_int length);
void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

/**
* GLOBALS
* [SOMEONE(source)] <-> [ME(target)] <-> [DESTINATION(router)]
*/
u_char sourceIPAddr[kMaxIPLen];
u_char sourceMac[kMaxMacLen];
u_char destinationIPAddr[kMaxIPLen];
u_char destinationMac[kMaxMacLen];
u_char interface[kMaxInterfaceLen];

int main(int argc, char *argv[]) {
	if (argc < kNeededArgsQty) {
	  showTips(argv[0]);

	  exit(EXIT_FAILURE);
	}

  initGlobals(argv);

  char errBuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcapHandle;

  /**
  * Open in non-promiscuous mode
  */
  pcapHandle = pcap_open_live(interface, 128, 0, 0, errBuf);
  if (pcapHandle == NULL) {
    printf("Couldn't open device %s: %s\n", interface, errBuf);
    return(EXIT_FAILURE);
  }

  char BPF[128] = "ip host ";
  sprintf(BPF, "ip dst host %s || ip dst host %s", sourceIPAddr, destinationIPAddr);

  struct bpf_program compiledBPF;
  if (pcap_compile(pcapHandle, &compiledBPF, BPF, 0, 0) == -1) {
    printf("Couldn't parse filter %s: %s\n", BPF, pcap_geterr(pcapHandle));
    return(EXIT_FAILURE);
  }

  if (pcap_setfilter(pcapHandle, &compiledBPF) == -1) {
    printf("Couldn't set filter %s: %s\n", BPF, pcap_geterr(pcapHandle));
    return(EXIT_FAILURE);
  }

	pcap_loop(pcapHandle, 0, gotPacket, NULL);

	pcap_close(pcapHandle);
  exit(0);
}

void gotPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	int tcpHdrLength = 0;
	int totalHdrSize = 0;
	int pktDataLength = 0;
	u_char *pktData = NULL;

	printf("==== Got a %d byte packet ====\n", header->len);

	decodeEther(packet);
	decodeIP(packet + AM_ETHER_HDR_LEN);

	tcpHdrLength = decodeTCP(packet + AM_ETHER_HDR_LEN + sizeof(struct amIPHdr));
	totalHdrSize = AM_ETHER_HDR_LEN + sizeof(struct amIPHdr) + tcpHdrLength;
	pktData = (u_char*)packet + totalHdrSize;
	pktDataLength = header->len - totalHdrSize;

	if (pktDataLength > 0) {
		printf("\t\t\t%u bytes of packet data\n", pktDataLength);
		dump(pktData, pktDataLength);
	} else {
		printf("\t\t\tNo Packet Data");
	}
}

void dump(const u_char *dataBuffer, const u_int length) {
	u_char byte;
	u_int indexFirst = 0;
	u_int indexSecond = 0;
	for (indexFirst = 0; indexFirst < length; indexFirst++) {
		byte = dataBuffer[indexFirst];
		printf("%02x ", dataBuffer[indexFirst]);

		if (((indexFirst % 16) == 15)
				|| (indexFirst == length-1)) {
			for (indexSecond = 0; indexSecond < 15 - (indexFirst % 16); indexSecond++) {
				printf("   ");
			}

			printf("| ");
			for (indexSecond = (indexFirst - (indexFirst % 16)); indexSecond <= indexFirst; indexSecond++) {
				byte = dataBuffer[indexSecond];
				if ((byte > 31)
				 		&& (byte < 127)) {
					printf("%c", byte);
				} else {
					printf(".");
				}
			}
			printf("\n");
		}
	}
}

void decodeIP(const u_char *packet) {
	const struct amIPHdr *ipHdr = NULL;

	ipHdr = (const struct amIPHdr*)packet;
	printf("\t(( Layer 3 ::: IP Header ))\n");

	struct in_addr address;
	address.s_addr = ipHdr->ipSrcAddr;
	printf("\t( Source: %s\t", inet_ntoa(address));

	address.s_addr = ipHdr->ipDstAddr;
	printf("Destination: %s )\n", inet_ntoa(address));

	printf("\t( Type: %u\t", (u_int)ipHdr->ipType);
	printf("ID: %hu\tLength: %hu )\n", ntohs(ipHdr->ipID), ntohs(ipHdr->ipLength));
}

u_int decodeTCP(const u_char *packet) {
	u_int hdrSize = 0;
	const struct amTCPHdr *tcpHdr = NULL;

	tcpHdr = (const struct amTCPHdr*)packet;
	hdrSize = 4 * tcpHdr->tcpOffset;

	printf("\t\t{{ Layer 4 ::: TCP Header }}\n");
	printf("\t\t{ Source Port: %hu\t", ntohs(tcpHdr->tcpSrcPort));
	printf("Destination Port: %hu }\n", ntohs(tcpHdr->tcpDstPort));
	printf("\t\t{ Sequence #: %u\t", ntohl(tcpHdr->tcpSeq));
	printf("Ack #: %u }\n", ntohl(tcpHdr->tcpAck));
	printf("\t\t{ Header Size: %u\tFlags: ", hdrSize);

	if (tcpHdr->tcpFlags & TCP_FIN) {
		printf("FIN ");
	}
	if (tcpHdr->tcpFlags & TCP_SYN) {
		printf("SYN ");
	}
	if (tcpHdr->tcpFlags & TCP_RST) {
		printf("RST ");
	}
	if (tcpHdr->tcpFlags & TCP_PUSH) {
		printf("PUSH ");
	}
	if (tcpHdr->tcpFlags & TCP_ACK) {
		printf("ACK ");
	}
	if (tcpHdr->tcpFlags & TCP_URG) {
		printf("URG");
	}

	printf(" }\n");

	return hdrSize;
}

void decodeEther(const u_char *packet) {
	const struct amEtherHdr *etherHdr = NULL;

	etherHdr = (const struct amEtherHdr*)packet;
	printf("[[ Layer 2 ::: Ethernet Header ]]\n");
	printf("[ Source: %02x", etherHdr->etherSrcAddr[0]);
	int index = 0;
	for (index = 1; index < AM_ETHER_ADDR_LEN; index++) {
		printf(":%02x", etherHdr->etherSrcAddr[index]);
	}

	printf("\tDestination: %02x", etherHdr->etherDstAddr[0]);
	for (index = 1; index < AM_ETHER_ADDR_LEN; index++) {
		printf(":%02x", etherHdr->etherDstAddr[index]);
	}

	printf("\tType: %hu ]\n", etherHdr->etherType);
}

void initGlobals(char *argv[]) {
	if (strncmp(argv[1], INTERFACE_KEY, 2) == 0) {
	  strncpy(interface, argv[2], kMaxInterfaceLen);
	} else {
		goto ERROR_INIT_LABEL;
	}

	if (strncmp(argv[3], SOURCE_IP_KEY, 4) == 0) {
	  strncpy(sourceIPAddr, argv[4], kMaxIPLen);
	} else {
		goto ERROR_INIT_LABEL;
	}

	if (strncmp(argv[5], SOURCE_MAC_KEY, 3) == 0) {
	  strncpy(sourceMac, argv[6], kMaxMacLen);
	} else {
		goto ERROR_INIT_LABEL;
	}

	if (strncmp(argv[7], DESTINATION_IP_KEY, 4) == 0) {
		strncpy(destinationIPAddr, argv[8], kMaxIPLen);
	} else {
		goto ERROR_INIT_LABEL;
	}

	if (strncmp(argv[9], DESTINATION_MAC_KEY, 3) == 0) {
		strncpy(destinationMac, argv[10], kMaxMacLen);
	} else {
		goto ERROR_INIT_LABEL;
	}

	return;

ERROR_INIT_LABEL:
	showTips(argv[0]);
	exit(EXIT_FAILURE);
}

const uint8_t* getMac(u_char *macStr) {
	uint8_t *result = (uint8_t*)calloc(6, sizeof(uint8_t));

	sscanf(macStr
				, "%02X:%02X:%02X:%02X:%02X:%02X"
				, &result[0]
				, &result[1]
				, &result[2]
				, &result[3]
				, &result[4]
				, &result[5]
			);

	return result;
}

void showTips(char *name) {
	printf("Usage: %s %s <interface> %s <source_ip> %s <source_mac> %s <destination_ip> %s <destination_mac>\n"\
	, name\
	, INTERFACE_KEY\
	, SOURCE_IP_KEY\
	, SOURCE_MAC_KEY\
	, DESTINATION_IP_KEY\
	, DESTINATION_MAC_KEY\
	);
}
