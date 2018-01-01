#include <stdio.h>
#include <libnet.h>
#include <stdint.h>
#include <stdlib.h>

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

	libnet_t *lContext;
	char errBuf[LIBNET_ERRBUF_SIZE];

	uint8_t *pSourceMac;
	uint8_t *pDestMac;

	lContext = libnet_init(LIBNET_LINK_ADV, interface, errBuf);
	if (lContext == NULL) {
		printf("Can't init libnet context\n%s\n", errBuf);
		goto FREE_RESOURCE_LABEL;
	}

	uint32_t nSourceIP = libnet_name2addr4(lContext, sourceIPAddr, LIBNET_DONT_RESOLVE);
	if (nSourceIP == -1) {
		printf("Can't resolve source ip\n%s\n", libnet_geterror(lContext));
		goto FREE_RESOURCE_LABEL;
	}

	const uint32_t targetIP = libnet_get_ipaddr4(lContext);
	struct libnet_ether_addr *targetMac = libnet_get_hwaddr(lContext);

	pSourceMac = getMac(sourceMac);
	uint32_t nDestIP = libnet_name2addr4(lContext, destinationIPAddr, LIBNET_DONT_RESOLVE);
	libnet_ptag_t lArp = libnet_autobuild_arp(
																						ARPOP_REPLY
																						, targetMac->ether_addr_octet
																						, (uint8_t*)&nDestIP
																						, pSourceMac
																						, (uint8_t*)&nSourceIP
																						, lContext
																					);

	if (lArp == -1) {
		printf("Can't init libnet context\n%s\n", errBuf);
		goto FREE_RESOURCE_LABEL;
	}

	if (libnet_autobuild_ethernet(pSourceMac, ETHERTYPE_ARP, lContext) == -1) {
		printf("Can't build ethernet\n%s\n", libnet_geterror(lContext));
		goto FREE_RESOURCE_LABEL;
	}

	int nBytesWriten = libnet_write(lContext);
	if (nBytesWriten == -1) {
		printf("Can't write\n%s\n", libnet_geterror(lContext));
	} else {
		printf("ToSource -> Wrote %d byte ARP packet from context %s\n"
					, nBytesWriten
					, libnet_cq_getlabel(lContext));
	}

	libnet_clear_packet(lContext);

	if (nDestIP == -1) {
		printf("Can't resolve destination ip\n%s\n", libnet_geterror(lContext));
		goto FREE_RESOURCE_LABEL;
	}

	lArp = libnet_autobuild_arp(
															ARPOP_REPLY
															, targetMac->ether_addr_octet
															, (uint8_t*)&nSourceIP
															, pDestMac
															, (uint8_t*)&nDestIP
															, lContext
														);

	pDestMac = getMac(destinationMac);
	if (libnet_autobuild_ethernet(pDestMac, ETHERTYPE_ARP, lContext) == -1) {
		printf("Can't build ethernet\n%s\n", libnet_geterror(lContext));
		goto FREE_RESOURCE_LABEL;
	}

	nBytesWriten = libnet_write(lContext);
	if (nBytesWriten == -1) {
		printf("Can't write\n%s\n", libnet_geterror(lContext));
	} else {
		printf("ToDestination -> Wrote %d byte ARP packet from context %s\n"
					, nBytesWriten
					, libnet_cq_getlabel(lContext));
	}

	libnet_destroy(lContext);
	free(((void*)pSourceMac));
	free(((void*)pDestMac));
	exit(0);

FREE_RESOURCE_LABEL:
	libnet_destroy(lContext);
	free(((void*)pSourceMac));
	free(((void*)pDestMac));
	exit(EXIT_FAILURE);
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
