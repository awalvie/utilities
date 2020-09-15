/* how the code should work in my head */
/* start the program */
/* refresh every 0.5s and show current download and upload rate*/

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>

#define PACKET_COUNT 10
#define KILOBYTE (double)1024
#define MEGABYTE (double)(1024 * 1024)

int main(void)
{
	int errno;
	double download_speed;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];

	time_t before;
	const u_char *packet;
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
		download_speed = 0;
		before = time(NULL);
		if (before == (time_t)(-1)) {
			fprintf(stderr, "ERROR: Could not set start time");
			exit(EXIT_FAILURE);
		}

		while (difftime(time(NULL), before) != 1) {
			if ((packet = pcap_next(capturedev, &packet_header)) !=
			    NULL) {
				download_speed += packet_header.len;
			}
		}

		if (download_speed / KILOBYTE > 1024) {
			printf("\rDownload Speed: %f MB/s",
			       download_speed / MEGABYTE);
			fflush(stdout);
		} else if (download_speed < 1024) {
			printf("\rDownload Speed: %f B/s",
			       download_speed);
			fflush(stdout);
		} else {
			printf("\rDownload Speed: %f KB/s",
			       download_speed / KILOBYTE);
			fflush(stdout);
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
