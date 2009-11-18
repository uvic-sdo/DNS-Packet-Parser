#include <assert.h>
#include <pcap.h>
#include <pcap/pcap.h>

#include <stdio.h>
#include <arpa/inet.h>

#include "structures.h"
#include "print.h"

// global variables
#define MAX_PACKET_SIZE 1518
#define NUM_PACKETS 1
pcap_t *device_handle;

// functions
pcap_t* create_handle(char *defined_device);
 
// callback function that is passed to pcap_loop(..) and called each time 
// a packet is recieved
void packet_callback(unsigned char *useless, const struct pcap_pkthdr* pkthdr, const unsigned char* packet){
	
	// cast the packet
	packet_desc *pd = (packet_desc*)packet;	

	int time = pkthdr->ts.tv_sec * 1000000.0 + pkthdr->ts.tv_usec;;
	printf("received at %d a packet: %d/%d\n", time, pkthdr->caplen, pkthdr->len);
	
	// only deal with dns packets
	// really should be done with filter
//	if( ntohs(pd->udp.dport)==53 ){
		print_packet(pd);
		printf("\n");
//	}

}



int main(){

	printf("starting\n");

	// connect and open the network connection
	device_handle = create_handle("wlan0");

	// call "pakcet_callback" for each sniffed packet
	pcap_loop(device_handle, NUM_PACKETS, packet_callback, NULL);

	// finish
	printf("Disconnecting\n");
	pcap_close(device_handle);
	return 0;
}



pcap_t* create_handle(char *defined_device) {
	printf("creating device handle & filter\n");
	int rv = 0;

	// device handle
	char *dev = defined_device;		/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	// filter
	char filter_exp[] = "udp port 53";		/* filter expression [3] */
	//struct bpf_program fp;			/* compiled filter program (expression) */
	//bpf_u_int32 mask = 0;			/* subnet mask */
	//bpf_u_int32 net = 0xffffffff;			/* ip */
	//int num_packets = 10;			/* number of packets to capture */

	//handle = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	
	// Create a device handle
	handle  = pcap_create(dev, errbuf);	// create the handle
	assert(handle != NULL);

	//int ret2 = pcap_compile(handle, &fp, filter_exp, 0, net); // create the filter
	//int ret3 = pcap_setfilter(handle, &fp); // attach the filter to the handle
	
	// Turn the handled device into monitor mode
	printf("canset: %d\n", pcap_can_set_rfmon(handle));
//	rv = pcap_set_rfmon(handle, 1);	// set monitor mode
	assert(rv==0);

	// Turn on the hadled device for lisening
	rv = pcap_activate(handle);	// start listening
	printf("activating:%d \n", rv);
	assert(rv==0);

	/* print capture info */	
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", NUM_PACKETS);
	printf("Filter expression: %s\n", filter_exp);
	printf("Link type: %d\n", pcap_datalink(handle) );
	return handle;
}
