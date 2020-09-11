/* how the code should work in my head */
/* start the program */
/* refresh every 0.5s and show current download and upload rate*/

#define PACKET_COUNT 10

#include <errno.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	int errno, i;
	const u_char *packet;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	static struct pcap_pkthdr packet_header;

	pcap_if_t *alldevsp;
	pcap_t *capturedev;

	/* get list of all network devices into structure */
	if ((errno = pcap_findalldevs(&alldevsp, errbuf)) != 0) {
		fprintf(stderr, "ERROR: %s", errbuf);
		exit(EXIT_FAILURE);
	}

	/* get the name of the first device on the list */
	dev = alldevsp->name;

	if (strcmp(dev, "") == 0) {
		fprintf(stdout, "No Devices Found!");
		exit(EXIT_SUCCESS);
	}

	if ((capturedev = pcap_create(dev, errbuf)) == NULL) {
		fprintf(stderr, "ERROR: %s", errbuf);
		exit(EXIT_FAILURE);
	}

	if ((pcap_set_timeout(capturedev, 1)) != 0) {
		fprintf(stderr, "ERROR: Unable to configure timeout.\n");
		exit(EXIT_FAILURE);
	}

	/* activate the device for capture */
	if ((errno = pcap_activate(capturedev)) > 0) {
		fprintf(stderr, "WARNING: %s", pcap_statustostr(errno));
	} else if (errno < 0) {
		fprintf(stderr, "ERROR: %s", pcap_statustostr(errno));
		exit(EXIT_FAILURE);
	}

	while (1) {
		if ((packet = pcap_next(capturedev, &packet_header)) != NULL) {
			printf("Packet length: %d\n", packet_header.len);
			printf("Packet timestamp: %ld\n",
			       packet_header.ts.tv_sec);
			printf("Packet caplen: %d\n", packet_header.caplen);
		}
	}

	/* close the activated device */
	if (capturedev) {
		pcap_close(capturedev);
	}

	/* free all devices */
	if (alldevsp)
		pcap_freealldevs(alldevsp);

	exit(EXIT_SUCCESS);
}
