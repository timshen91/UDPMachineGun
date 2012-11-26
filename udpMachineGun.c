#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/ip.h>
#include <linux/udp.h>

int mode; // 0 : server, 1 : client
uint16_t truePort, lPort, rPort;
int count = 0;

uint16_t checksum(uint32_t sum, uint16_t * buf, int size) {
	while (size > 1) {
		sum += *buf++;
		size -= sizeof(uint16_t);
	}
	if (size)
		sum += *(uint8_t *)buf;

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >>16);

	return (uint16_t)(~sum);
}

void udpChecksum(struct iphdr * iph, struct udphdr * uhdr) {
	uint32_t sum = 0;
	uint32_t iph_len = iph->ihl * 4;
	uint32_t len = ntohs(iph->tot_len) - iph_len;
	uint8_t * payload = (uint8_t *)iph + iph_len;
	
	uhdr->check = 0;

	sum += (iph->saddr >> 16) & 0xFFFF;
	sum += (iph->saddr) & 0xFFFF;
	sum += (iph->daddr >> 16) & 0xFFFF;
	sum += (iph->daddr) & 0xFFFF;
	sum += htons(IPPROTO_UDP);
	sum += htons(len);

	uhdr->check = checksum(sum, (uint16_t *)payload, len);
}

void subst(struct iphdr * iphdr, struct udphdr * uhdr, uint16_t * old, uint16_t newPort) {
	*old = newPort;
	udpChecksum(iphdr, uhdr);
}

int inHandler(struct nfq_q_handle * qh, struct nfgenmsg * nfmsg, struct nfq_data * nfad, void * data) {
	struct nfqnl_msg_packet_hdr * ph;
	int id;
	if ((ph = nfq_get_msg_packet_hdr(nfad))) {
		id = ntohl(ph->packet_id);
	}
	struct iphdr * iphdr;
	int pdata_len;
	if ((pdata_len = nfq_get_payload(nfad, (unsigned char **)&iphdr)) == -1) {
		pdata_len = 0;
	}
	if (iphdr->protocol == 17) {
		struct udphdr * uhdr = (struct udphdr *)((unsigned char *)iphdr + iphdr->ihl * 4);
		if (mode == 1) {
			if (lPort <= ntohs(uhdr->source) && ntohs(uhdr->source) < rPort) {
				subst(iphdr, uhdr, &uhdr->source, htons(truePort));
			}
		} else {
			if (lPort <= ntohs(uhdr->dest) && ntohs(uhdr->dest) < rPort) {
				subst(iphdr, uhdr, &uhdr->dest, htons(truePort));
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, pdata_len, (const unsigned char *)iphdr);
}

int outHandler(struct nfq_q_handle * qh, struct nfgenmsg * nfmsg, struct nfq_data * nfad, void * data) {
	struct nfqnl_msg_packet_hdr * ph;
	int id;
	if ((ph = nfq_get_msg_packet_hdr(nfad))) {
		id = ntohl(ph->packet_id);
	}
	struct iphdr * iphdr;
	int pdata_len;
	if ((pdata_len = nfq_get_payload(nfad, (unsigned char **)&iphdr)) == -1) {
		pdata_len = 0;
	}
	if (iphdr->protocol == 17) {
		struct udphdr * uhdr = (struct udphdr *)((unsigned char *)iphdr + iphdr->ihl * 4);
		if (mode == 1) {
			if (ntohs(uhdr->dest) == truePort) {
				subst(iphdr, uhdr, &uhdr->dest, htons(rand() % (rPort - lPort) + lPort));
				printf("%d\n", count++);
			}
		} else {
			if (ntohs(uhdr->source) == truePort) {
				subst(iphdr, uhdr, &uhdr->source, htons(rand() % (rPort - lPort) + lPort));
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, pdata_len, (const unsigned char *)iphdr);
}

int main(int argc, char * argv[]) {
	if (argc < 5) {
		return 1;
	}
	if (strcmp(argv[1], "server") == 0) {
		mode = 0;
	} else {
		mode = 1;
	}
	truePort = atoi(argv[2]);
	lPort = atoi(argv[3]);
	rPort = atoi(argv[4]);
	struct nfq_handle * h;
	if ((h = nfq_open()) == 0) {
		perror("");
		return 1;
	}
	nfq_bind_pf(h, AF_INET);
	struct nfq_q_handle * qh;
	if ((qh = nfq_create_queue(h, 2012, inHandler, 0)) == 0) {
		perror("");
		return 1;
	}
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) == -1) {
		perror("");
		return 1;
	}
	if ((qh = nfq_create_queue(h, 2013, outHandler, 0)) == 0) {
		perror("");
		return 1;
	}
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) == -1) {
		perror("");
		return 1;
	}
	int fd = nfq_fd(h);
	int count;
	char buff[0xffff];
	while (1) {
		if ((count = recv(fd, buff, sizeof(buff), 0)) >= 0) {
			nfq_handle_packet(h, buff, count);
		}
	}
	nfq_close(h);
	return 0;
}
