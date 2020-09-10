/* how the code should work in my head */
/* start the program */
/* refresh every 0.5s and show current download and upload rate*/

#include <errno.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
	int errno;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevsp;

	/* get list of all network devices into structure */
	if ((errno = pcap_findalldevs(&alldevsp, errbuf)) != 0) {
		perror("ERROR: ");
		exit(EXIT_FAILURE);
	} else if (strcmp(alldevsp->name, " ") == 0) {
		fprintf(stdout, "No Devices Found!");
		exit(EXIT_SUCCESS);
	}

	puts(alldevsp->name);

	/* free all devices */
	if (alldevsp)
		pcap_freealldevs(alldevsp);

	exit(EXIT_SUCCESS);
}
