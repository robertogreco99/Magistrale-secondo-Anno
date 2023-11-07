// Standard C include file for I/O functions
#include <stdio.h>
// Include files for libpcap functions
#include <pcap.h>
// erPer le stringhe
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>

#define MAXBYTES2CAPTURE 2048

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet header */
struct sniff_ethernet
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};
/* IP header */
struct sniff_ip
{
    u_char ip_vhl;                /* version << 4 | header length >> 2 */
    u_char ip_tos;                /* type of service */
    u_short ip_len;               /* total length */
    u_short ip_id;                /* identification */
    u_short ip_off;               /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    u_char ip_ttl;                /* time to live */
    u_char ip_p;                  /* protocol */
    u_short ip_sum;               /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
    u_short th_sport; /* source port */
    u_short th_dport; /* destination port */
    tcp_seq th_seq;    /* sequence number */
    tcp_seq th_ack;    /* acknowledgement number */
    u_char th_offx2;  /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

void processPacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet) 
  
{
    int i = 0, *counter = (int *)arg;
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip;             /* The IP header */
    const struct sniff_tcp *tcp;           /* The TCP header */
    const char *payload;                   /* Packet payload */

    u_int size_ip;
    u_int size_tcp;
    u_int size_payload;

    //ethernet  inizializzato con l'indirizzo iniziale del pacchetto
    ethernet = (struct sniff_ethernet *)(packet);

    //printf("Packet count : %d\n", ++(*counter));
    //printf("Received packet size lenght : %d\n", pkthdr->len);
    //printf("Payload :\n");
    //printf("Timestamp:%ld:%ld\n",pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);


    //stampa  dei mac
   /* printf("----Mac----\n");
    printf("%02x:%02x:%02x:%02x:%02x:%02x --> %02x:%02x:%02x:%02x:%02x:%02x\n\n",ethernet->ether_shost[0],
    ethernet->ether_shost[1],ethernet->ether_shost[2],ethernet->ether_shost[3],ethernet->ether_shost[4],ethernet->ether_shost[5],
    ethernet->ether_dhost[0],ethernet->ether_dhost[1],ethernet->ether_dhost[2],ethernet->ether_dhost[3],ethernet->ether_dhost[4],
    ethernet->ether_dhost[5]);*/

    //ip  inizializzato con l'indirizzo iniziale del pacchetto
    //+ la dimensione di ethernet che è fissa
    ip = (struct sniff_ip *)(packet + SIZE_ETHERNET);

//IP_HL è una macro definita come (((ip)->ip_vhl) & 0x0f) 
//Restituisce la lunghezza dell'header IP in parole da 32 bit. 
//Il campo ip_vhl dell'header IP contiene informazioni sia sulla versione che sulla lunghezza dell'header IP. 
//Moltiplicando il valore ottenuto per 4 si converte da parole da 32 bit a byte.
    size_ip = IP_HL(ip) * 4;
    //Verifica lunghezza ip : 20 valore minimo corretto 
    if (size_ip < 20)
    {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    /* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	/*switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}*/
    /* Ottiene un puntatore alla struttura sniff_tcp saltando sia l'header  Ethernet che l'header IP. 
    Aggiunge la lunghezza dell'header IP al punto iniziale del pacchetto per puntare all'header TCP.*/
    tcp = (struct sniff_tcp *)(packet + SIZE_ETHERNET + size_ip);
    /* TH_OFF è una macro definita come (((tcp)->th_offx2 & 0xf0) >> 4). 
    Restituisce la lunghezza dell'header TCP in parole da 32 bit. 
    Moltiplicando il valore ottenuto per 4 si converte da parole da 32 bit a byte*/
    size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20)
     //Verifica lunghezza tcp : 20 valore minimo corretto 
    {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
     //porte
    //printf("   Src port: %d\n", ntohs(tcp->th_sport));
	//printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    

    /*payload è un puntatore al payload del pacchetto.
     Aggiunge la somma della lunghezza dell'header Ethernet, IP e TCP per puntare al payload, 
     ovvero i dati del pacchetto dopo gli header Ethernet, IP e TCP. */
    payload = (u_short*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    /* compute tcp payload (segment) size */
	//size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    /*
	 * Print payload data; it might be binary, so don't just
	 * treat it as a string.
	 */
	/*if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
        //print_payload(payload, size_payload);
	}*/

    if(ntohs(tcp->th_dport ) == 80) {
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        if(size_payload  > 0) {
            char* http_request = (char*) payload;
            printf("%s",http_request);
             if(strncmp(http_request,"GET",4) == 0 ||
               strncmp(http_request,"POST",5) == 0  ||
               strncmp(http_request,"PUT",4) == 0 ||
               strncmp(http_request,"DELETE",7) == 0 
             ) {
                printf("HTTP request : %s",http_request);
             }
        }
    }
    

}
int main()
{

    int i = 0, count = 0;
    pcap_t *handle = NULL;
    char errbuf[PCAP_ERRBUF_SIZE], *device = NULL;
    memset(errbuf, 0, PCAP_ERRBUF_SIZE); // alloco la memoria

    // trova la prima interfaccia che può leggere traffico
    device = pcap_lookupdev(errbuf);
    if (device == NULL)
    {
        printf("Couldn't find device : %s\n", errbuf);
        return 2;
    }
    printf("Opening device %s\n", device);
    // Apro il device per lo sniffing

    /*apro in modalità promiscua*/
    handle = pcap_open_live(device, MAXBYTES2CAPTURE, 1, 512, errbuf);

    if (handle == NULL)
    {
        printf("Error in opening device %s :%s\n", device, errbuf);
        return 3;
    }

    /*loop dove chiamo ogni volta la funzione*/
    pcap_loop(handle, -1, processPacket, (u_short *)&count);
    pcap_close(handle);

    return 0;
}