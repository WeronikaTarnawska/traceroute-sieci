/* Weronika Tarnawska 331171 */
#include <sys/cdefs.h>
// #include <features.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <sys/time.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>

#define TTL_START 1
#define TTL_END 30
#define PACKETS_PER_TURN 3
#define IP_STR_MAXLEN 20

void panic(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

uint16_t compute_icmp_checksum(const void *buff, int length)
{
	uint32_t sum;
	const uint16_t *ptr = buff;
	assert(length % 2 == 0);
	for (sum = 0; length > 0; length -= 2)
		sum += *ptr++;
	sum = (sum >> 16) + (sum & 0xffff);
	return (uint16_t)(~(sum + (sum >> 16)));
}

void print(int ttl, char ips[PACKETS_PER_TURN][IP_STR_MAXLEN], int received_cnt, char *target_ip, double timediff[PACKETS_PER_TURN])
{
	printf("%2.d  ", ttl);
	if (received_cnt == 0)
	{
		printf("*\n");
		return;
	}
	int target_reached = 0;
	double timesum = 0;
	for (int i = 0; i < received_cnt; i++)
	{
		int repeats = 0;
		for (int j = 0; j < i; j++)
			if (strncmp(ips[i], ips[j], IP_STR_MAXLEN) == 0)
				repeats = 1;
		if (!repeats)
		{
			printf("%16s ", ips[i]);
			if (strncmp(ips[i], target_ip, IP_STR_MAXLEN) == 0)
			{
				target_reached = 1;
			}
		}
		timesum += timediff[i];
	}
	if (received_cnt < PACKETS_PER_TURN)
	{
		printf("???\n");
	}
	else
	{
		printf("%10.3lfms\n", timesum / PACKETS_PER_TURN);
	}
	if (target_reached)
		exit(EXIT_SUCCESS);
}

int receive_packets(int sockfd, char response_ip[PACKETS_PER_TURN][IP_STR_MAXLEN], int ttl, double timediff[PACKETS_PER_TURN])
{
	fd_set readfds;
	FD_ZERO(&readfds);
	FD_SET(sockfd, &readfds);
	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	int received_cnt = 0;
	int i = 0;
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);
	while (i < PACKETS_PER_TURN)
	{
		int ready = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
		if (ready < 0)
			panic("Select error");
		if (ready == 0)
		{
			// printf("no more packets or timeout\n");
			return received_cnt;
		}
		struct sockaddr_in src_addr;
		socklen_t addrlen = sizeof(src_addr);
		uint8_t buf[IP_MAXPACKET];
		ssize_t msg_len = recvfrom(sockfd, buf, IP_MAXPACKET, MSG_DONTWAIT, (struct sockaddr *)&src_addr, &addrlen);
		gettimeofday(&t2, NULL);

		if (msg_len < 0)
			panic("Recvfrom error");
		if (msg_len == 0)
		{
			// printf("No more packets\n");
			return received_cnt;
		}
		if (inet_ntop(AF_INET, &(src_addr.sin_addr), response_ip[i], IP_STR_MAXLEN) == NULL)
			panic("Inet_ntop error");
		struct iphdr *ip_header = (struct iphdr *)buf;
		u_int8_t *icmp_packet = buf + 4 * ip_header->ihl;
		struct icmphdr *icmp_header = (struct icmphdr *)icmp_packet;
		// printf(">>> %d\n", icmp_header->type);
		if (icmp_header->type == ICMP_ECHOREPLY)
			;
		else if (icmp_header->type == ICMP_TIME_EXCEEDED)
		{
			ip_header = (void *)icmp_header + 8;
			icmp_header = (void *)ip_header + 4 * ip_header->ihl;
		}
		else
			continue;
		if ((icmp_header->un.echo.sequence >> 2) == ttl && icmp_header->un.echo.id == (uint16_t)getpid())
		{
			timediff[i] = (double)1000 * (t2.tv_sec - t1.tv_sec) + ((double)(t2.tv_usec - t1.tv_usec)) / 1000;
			received_cnt++;
			i++;
		}
	}
	return received_cnt;
}

void send_packets(int sockfd, int ttl, char *ip_addr)
{
	for (uint16_t i = 0; i < PACKETS_PER_TURN; i++)
	{
		/* icmp header */
		struct icmphdr header;
		header.type = ICMP_ECHO;
		header.code = 0;
		header.un.echo.id = (uint16_t)getpid();
		header.un.echo.sequence = ((uint16_t)ttl << 2) | (i & 3);
		header.checksum = 0;
		header.checksum = compute_icmp_checksum((u_int16_t *)&header, sizeof(header));

		/* destination address */
		struct sockaddr_in dest_addr;
		bzero(&dest_addr, sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;
		int succ = inet_pton(AF_INET, ip_addr, &dest_addr.sin_addr);
		if (succ < 0)
			panic("Inet_pton error");
		else if (succ == 0)
			panic("Inet_pton: Invalid network address");

		/* set ttl */
		if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0)
			panic("Setsockopt error");

		ssize_t bytes_sent = sendto(sockfd, &header, sizeof(header), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
		if (bytes_sent < 0)
			panic("Sendto error");
	}
}

// for ttl in [1, 30]
// 	wyślij 3 pakiety icmp echo request (send)
//  odbierz te pakiety, ale nie czekaj dłużej niż 1s (receive)
//  wyświetl ip routera z którego przyszły odpowiedzi i średni czas oczekiwania (print)
//  if ip_returned == target_ip
//   return

int main(int argc, char **argv)
{
	if (argc != 2)
	{
		fprintf(stderr, "Usage:\t./traceroute [ip address]\n");
		exit(EXIT_FAILURE);
	}

	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0)
		panic("Socket error");
	struct sockaddr addr;
	addr.sa_family = AF_INET;
	strncpy(addr.sa_data, argv[1], 14);
	if (bind(sockfd, &addr, sizeof(addr)) > 0)
		panic("Bind error");

	for (int ttl = TTL_START; ttl <= TTL_END; ttl++)
	{
		send_packets(sockfd, ttl, argv[1]);
		char response_ip[PACKETS_PER_TURN][IP_STR_MAXLEN];
		double timediff[PACKETS_PER_TURN];
		int received_cnt = receive_packets(sockfd, response_ip, ttl, timediff);
		print(ttl, response_ip, received_cnt, argv[1], timediff);
	}
}
