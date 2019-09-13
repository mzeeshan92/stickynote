#include <stdio.h>
#include <pcap.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header,
	    const u_char *packet);

int main(int argc, char *argv[])
	{
		char *dev , errbuf[PCAP_ERRBUF_SIZE];
		dev = argv[1];
		pcap_t *handle;
		struct pcap_pkthdr header;	/* The header that pcap gives us */
		const u_char *packet;		/* The actual packet */

		printf("Device: %s\n", dev);
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	 	if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 	return(2);
	 	}
	 	else{
			 printf("\n handle: %p", handle);
		 }

		if (pcap_datalink(handle) != DLT_EN10MB) {
			fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}

	pcap_loop(handle, -5, got_packet, NULL);
	/* Print its length */
	//printf("\nJacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	// pcap_close(handle);
	return(0);
	}
	void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
		printf("\n length of the packet: %u",header->len);

		}