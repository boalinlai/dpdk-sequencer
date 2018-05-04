/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>  // for close
// fa:16:3e:19:34:cf
#define DEST_MAC0 0xfa
#define DEST_MAC1 0x16
#define DEST_MAC2 0x3e
#define DEST_MAC3 0x19
#define DEST_MAC4 0x34
#define DEST_MAC5 0xcf
#define ETHER_TYPE 0x0000

#define DEFAULT_IF "ens3"
#define BUF_SIZ 1024
#define LIMIT 100000

void slice_str(const char *str, char *buffer, size_t start, size_t end) {
  size_t j = 0;
  for (size_t i = start; i <= end; ++i) {
    buffer[j++] = str[i];
  }
  buffer[j] = 0;
}

unsigned long parser_pkt_buffer(const char *str, size_t start, size_t end) {
  size_t j = 0;
  char buffer[100];
  for (size_t i = start; i <= end; ++i) {
    buffer[j++] = str[i];
  }
  buffer[j] = 0;
  return atoll(buffer);
}

int main(int argc, char *argv[]) {
  char sender[INET6_ADDRSTRLEN];
  int sockfd, ret, i;
  int sockopt = 1;
  ssize_t numbytes;
  struct ifreq ifopts; /* set promiscuous mode */
  struct ifreq if_ip;  /* get ip addr */
  struct sockaddr_storage their_addr;
  uint8_t buf[BUF_SIZ];
  char ifName[IFNAMSIZ];

  struct timeval tv;

  int time_in_mill;
  char time_str[100];
  int count = 0;
  unsigned long total_us = 0;
  /* Get interface name */
  if (argc > 1)
    strcpy(ifName, argv[1]);
  else
    strcpy(ifName, DEFAULT_IF);

  /* Header structures */
  struct ether_header *eh = (struct ether_header *)buf;
  struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct ether_header));
  struct udphdr *udph = (struct udphdr *)(buf + sizeof(struct iphdr) +
                                          sizeof(struct ether_header));

  memset(&if_ip, 0, sizeof(struct ifreq));
  // htons(ETH_P_ALL)
  /* Open PF_PACKET socket, listening for EtherType ETHER_TYPE */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    perror("listener: socket");
    return -1;
  }

  /* Set interface to promiscuous mode - do we need to do this every time? */
  strncpy(ifopts.ifr_name, ifName, IFNAMSIZ - 1);
  ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
  ifopts.ifr_flags |= IFF_PROMISC;
  ioctl(sockfd, SIOCSIFFLAGS, &ifopts);
  /* Allow the socket to be reused - incase connection is closed prematurely */
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof sockopt) ==
      -1) {
    perror("setsockopt");
    close(sockfd);
    exit(EXIT_FAILURE);
  }
  /* Bind to device */
  if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ - 1) ==
      -1) {
    perror("SO_BINDTODEVICE");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

repeat:
  if (count >= LIMIT) {
    printf("result: %lu (us)\n", total_us / LIMIT);
    return 0;
  }
  numbytes = recvfrom(sockfd, buf, BUF_SIZ, 0, NULL, NULL);

  /* Check the packet is for me */
  if (eh->ether_dhost[0] == DEST_MAC0 && eh->ether_dhost[1] == DEST_MAC1 &&
      eh->ether_dhost[2] == DEST_MAC2 && eh->ether_dhost[3] == DEST_MAC3 &&
      eh->ether_dhost[4] == DEST_MAC4 && eh->ether_dhost[5] == DEST_MAC5 &&
      eh->ether_shost[3] == 0xc9 && eh->ether_shost[4] == 0x64 &&
      eh->ether_shost[5] == 0x80) {
    printf("\tData:");
    for (i = 0; i < numbytes; i++) {
      printf("%02x:", buf[i]);
    }
    printf("\n");

    int index;
    for (i = 0; i < numbytes; i++) {
      if (buf[i] == 170 && buf[i + 1] == 170 && buf[i + 2] == 170 &&
          buf[i + 3] == 170) {
        index = i + 4;
        // printf("%d\n", index);
      }
    }

    gettimeofday(&tv, NULL);

    unsigned long recver_ts = ((tv.tv_sec) * 1000 * 1000) + (tv.tv_usec);

    unsigned long sender_ts = parser_pkt_buffer(buf, index, numbytes - 1);
    /*
            printf("sender:%lu\n", sender_ts);
            printf("recver:%lu\n", recver_ts);
            printf("ts diff:%lu (us) \n", recver_ts - sender_ts);
            printf("count:%d\n", count);
    */
    count++;
    total_us += recver_ts - sender_ts;
    // printf("recv packet from seq\n");
    printf("seq count: %d\n", count);

  } else {
    ret = -1;
    goto done;
  }
  /* UDP payload length */
  ret = ntohs(udph->len) - sizeof(struct udphdr);
// filter only the src is dpdk nic:

done:
  goto repeat;

  close(sockfd);
  return ret;
}
