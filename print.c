#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "structures.h"

void print_mac(unsigned char* mac){
	int i;
	for(i=0; i<6; i++){
		if(i!=0) printf(":");
		printf("%X",mac[i]);
	}
}

char* print_url(char data[]){
	int i=0;
	int toread = data[0];
	int start = 0;
	i++;


	while(toread != 0){
		// print the (#) where a "." in the url is
		//printf("(%d)", toread);
		printf(".");

		// print everything bettween the dots
		for(; i<=start+toread; i++)
			printf("%c",data[i]);
		
		// next chunk
		toread = data[i];
		start = i;
		i++;
	}

	// return a char* to the first non-url char
	return &data[i];
}



int sizeofUrl(char data[]){
	int i = 0;
	int toskip = data[0];

	// skip each set of chars until (0) at the end
	while(toskip!=0){
		i += toskip+1;
		toskip = data[i];
	}

	// return the length of the array including the (0) at the end
	return i+1;
}
/*
char* getUrl(char data[]){
	int size = sizeofUrl(data)-2;
	//char *url = malloc(size);

	
	int i=0;
	int toread = data[0];
	int start = 0;
	i++;
	int j = 0;

	while(toread != 0){
		// a "." in the url
		if(start!=0){
			url[j] = ".";
			j++;
		}	

		// print everything bettween the dots
		for(; i<=start+toread; i++){
			url[j] = data[i];
			j++;
		}

		// next chunk
		toread = data[i];
		start = i;
		i++;
	}

}
*/
void printRRType(int i){
	switch(i){
		case 1:
			printf("IPv4 address record");
			break;
		case 15:
			printf("MX mail exchange record");
			break;
		case 18:
			printf("AFS database record");
			break;
		case 28:
			printf("IPv6 address record");
			break;
		default:
			printf("unknown (%d)",i);
	}
}

void print_packet(void *pack){
	char *tab = "   ";
	
	// listening with an eth header	
	packet_desc* pd = (packet_desc*)pack;
	int offset = pd->wifi.len - sizeof(pd->wifi);

	printf("IEEE 802.11 HEADER\n");
	printf("%sversion:%d\n", tab, pd->wifi.version );
	printf("%spad:%d\n", tab, pd->wifi.pad );
	printf("%slength:%d extra:%i \n", tab, pd->wifi.len, offset );
	printf("%sfields present:%8x\n", tab, pd->wifi.present );

	printf("LOGICAL LINK CONTROL HEADER\n");
	
	printf("IP HEADER\n");	
	printf("%ssource:%s\n", tab, inet_ntoa(pd->ip.src) );
	printf("%sdest:%s\n", tab, inet_ntoa(pd->ip.dst) );

	printf("UDP HEADER\n");	
	printf("%ssource port:%d\n", tab, ntohs(pd->udp.sport) );	
	printf("%sdest port:%d\n", tab, ntohs(pd->udp.dport) );	
	
	printf("DNS HEADER\n");
	printf("%sid:%d\n", tab, ntohs(pd->dns.id));
	printf("%sflags:%d\n", tab, ntohs(pd->dns.flags));
	printf("%s# questions:%d\n", tab, ntohs(pd->dns.qdcount));
	printf("%s# answers:%d\n", tab, ntohs(pd->dns.ancount));
	printf("%s# ns:%d\n", tab, ntohs(pd->dns.nscount));
	printf("%s# ar:%d\n", tab, ntohs(pd->dns.arcount));

	printf("RESOURCE RECORDS\n");

	int numRRs = ntohs(pd->dns.qdcount) + ntohs(pd->dns.ancount) + ntohs(pd->dns.nscount) + ntohs(pd->dns.arcount);
	int i;

	numRRs = 0;	
	for(i=0; i<numRRs; i++){
	//	printf("%sRR(%d)\n", tab, i);
		printf("(%d)", sizeofUrl(pd->data)-2); print_url(pd->data); printf("\n");

		// extract variables
		static_RR* RRd = (static_RR*)((void*)pd->data + sizeofUrl(pd->data));
		int type = ntohs(RRd->type);
		int clas = ntohs(RRd->clas);
		int ttl = (uint32_t)ntohl(RRd->ttl);
		int rdlength = ntohs(RRd->rdlength);
		uint8_t* rd = (void*)(&RRd->rdlength + sizeof(uint16_t));
	
		printf("%stype(%d):",tab,type); printRRType( ntohs(RRd->type) ); printf("\n");
		printf("%sclass:%d TTL:%d RDlength:%d\n", tab, clas, ttl, rdlength);
		if( rdlength != 0 ){
			printf("data:");
			printf("%d.%d.%d.%d",rd[0], rd[1], rd[2], rd[3]  );
			printf("\n");
		}

	}
	
}


