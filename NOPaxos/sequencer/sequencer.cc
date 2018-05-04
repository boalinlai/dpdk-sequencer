// -*- mode: c++; c-file-style: "k&r"; c-basic-offset: 4 -*-
/***********************************************************************
 *
 * sequencer/sequencer.cc:
 *   End-host network sequencer implementation.
 *
 * Copyright 2017 Jialin Li <lijl@cs.washington.edu>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 **********************************************************************/

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#include <iostream>
#include <fstream>
#include "lib/message.h"
#include "sequencer/sequencer.h"

using namespace std;
/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
// fa:16:3e:c9:64:80
// fa:16:3e:19:34:cf boa3
#define MY_DEST_MAC0 0xfa
#define MY_DEST_MAC1 0x16
#define MY_DEST_MAC2 0x3e
#define MY_DEST_MAC3 0x19
#define MY_DEST_MAC4 0x34
#define MY_DEST_MAC5 0xcf

#define DEFAULT_IF "ens3"
#define BUF_SIZ 1024

// need to rewrite the class for cacheing the socket data...

int cache_socket(int sockfd, uint8_t *sendbuf, int tx_len,
                 struct sockaddr_ll *socket_address) {
  return (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr *)socket_address,
                 sizeof(struct sockaddr_ll)));
}

namespace sequencer {

Sequencer::Sequencer(uint64_t sequencer_id) : sequencer_id(sequencer_id) {}

Sequencer::~Sequencer() {}

uint64_t Sequencer::Increment(uint32_t groupIdx) {
  if (this->counters.find(groupIdx) == this->counters.end()) {
    this->counters.insert(make_pair(groupIdx, 0));
  }

  return ++this->counters[groupIdx];
}

Configuration::Configuration(ifstream &file) {
  while (!file.eof()) {
    string line;
    getline(file, line);

    // Ignore comments
    if ((line.size() == 0) || (line[0] == '#')) {
      continue;
    }

    char *cmd = strtok(&line[0], " \t");

    if (strcasecmp(cmd, "interface") == 0) {
      char *arg = strtok(nullptr, " \t");
      if (!arg) {
        Panic("'interface' configuration line requires an argument");
      }

      char *iface = strtok(arg, "");

      if (!iface) {
        Panic("Configuration line format: 'interface name'");
      }

      this->interface = string(iface);
    } else if (strcasecmp(cmd, "groupaddr") == 0) {
      char *arg = strtok(nullptr, " \t");
      if (!arg) {
        Panic("'groupaddr' configuration line requires an argument");
      }

      char *gaddr = strtok(arg, "");

      if (!gaddr) {
        Panic("Configuration line format: 'groupaddr addr;");
      }
      this->groupAddr = string(gaddr);
    } else {
      Panic("Unknown configuration directive: %s", cmd);
    }
  }
}

Configuration::~Configuration() {}

string Configuration::GetInterface() { return this->interface; }

string Configuration::GetGroupAddr() { return this->groupAddr; }

Transport::Transport(Sequencer *sequencer, Configuration *config)
    : sequencer(sequencer), config(config), sockfd(-1) {
  struct ifreq ifopts;
  struct sockaddr_ll sll;
  int sockopt = 1;

  // if ((this->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE))) == -1)
  // {
  if ((this->sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
    Panic("Failed to open socket");
  }

  memset(&ifopts, 0, sizeof(ifopts));
  strncpy(ifopts.ifr_name, config->GetInterface().c_str(), IFNAMSIZ - 1);
  if (ioctl(this->sockfd, SIOCGIFINDEX, &ifopts) < 0) {
    Panic("Failed to set ioctl option SIOCGIFINDEX");
  }

  if (setsockopt(this->sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt,
                 sizeof(sockopt)) == -1) {
    Panic("Failed to set socket option SO_REUSEADDR");
  }

  bzero(&sll, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = ifopts.ifr_ifindex;

  if (bind(this->sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1) {
    Panic("Failed to bind socket");
  }

  /* Sequencer sends out packets using multicast */
  this->destSockAddr.sll_ifindex = ifopts.ifr_ifindex;
  this->destSockAddr.sll_halen = ETH_ALEN;

  // hard code the dest packet for now
  // fa:16:3e:19:34:cf boa3
  this->destSockAddr.sll_addr[0] = 0xfa;
  this->destSockAddr.sll_addr[1] = 0x16;
  this->destSockAddr.sll_addr[2] = 0x3e;
  this->destSockAddr.sll_addr[3] = 0x19;
  this->destSockAddr.sll_addr[4] = 0x34;
  this->destSockAddr.sll_addr[5] = 0xcf;

  /*
  for (int i = 0; i < ETH_ALEN; i++) {
      this->destSockAddr.sll_addr[i] = 0xFF;
  }
  */
}

Transport::~Transport() {
  if (sockfd != -1) {
    close(sockfd);
  }
}

void Transport::Run() {
  int n;
  uint8_t buffer[BUFFER_SIZE];

  int sockfd;
  struct ifreq if_idx;
  struct ifreq if_mac;
  //	int tx_len = 0;
  //	struct ether_header *eh = (struct ether_header *) sendbuf;
  //	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct
  // ether_header));
  struct sockaddr_ll socket_address;
  char ifName[IFNAMSIZ];

  /* Get interface name */
  strcpy(ifName, DEFAULT_IF);
  /* Open RAW socket to send on */
  if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
    perror("socket");
  }

  /* Get the index of the interface to send on */
  memset(&if_idx, 0, sizeof(struct ifreq));
  strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0) perror("SIOCGIFINDEX");
  /* Get the MAC address of the interface to send on */
  memset(&if_mac, 0, sizeof(struct ifreq));
  strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
  if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0) perror("SIOCGIFHWADDR");

  /* Index of the network device */
  socket_address.sll_ifindex = if_idx.ifr_ifindex;
  /* Address length*/
  socket_address.sll_halen = ETH_ALEN;
  /* Destination MAC */
  socket_address.sll_addr[0] = MY_DEST_MAC0;
  socket_address.sll_addr[1] = MY_DEST_MAC1;
  socket_address.sll_addr[2] = MY_DEST_MAC2;
  socket_address.sll_addr[3] = MY_DEST_MAC3;
  socket_address.sll_addr[4] = MY_DEST_MAC4;
  socket_address.sll_addr[5] = MY_DEST_MAC5;

  if (this->sockfd == -1) {
    Warning("Transport not registered yet");
    return;
  }

  while (true) {
    n = recvfrom(this->sockfd, buffer, BUFFER_SIZE, 0, nullptr, nullptr);

    if (n <= 0) {
      break;
    }
    if (ProcessPacket(buffer, n)) {
      // cout << "ready to send to boa3 ?" << endl;
      // need to rebind socket to boa3?
      if (cache_socket(sockfd, buffer, n, &socket_address) < 0) {
        Warning("Failed to send packet");
      }
      /*
                  if (sendto(dst, buffer, BUFFER_SIZE, 0,
                             (struct sockaddr*)&this->destSockAddr,
                             sizeof(struct sockaddr_ll)) < 0) {
                      Warning("Failed to send packet");
                  }
      */
    }
  }
}

bool Transport::ProcessPacket(uint8_t *packet, size_t len) {
  struct ether_header *eh;
  struct iphdr *iph;
  struct udphdr *udph;
  struct sockaddr_storage saddr;
  uint8_t *datagram, ngroups;
  char destip[INET6_ADDRSTRLEN];
  uint16_t group_bitmap;
  /*
      if (len < sizeof(struct ether_header) + sizeof(struct iphdr) +
     sizeof(struct udphdr)) {
          return false;
      }
  */
  eh = (struct ether_header *)packet;
  iph = (struct iphdr *)(packet + sizeof(struct ether_header));
  udph = (struct udphdr *)(packet + sizeof(struct ether_header) +
                           sizeof(struct iphdr));
  datagram = (uint8_t *)(packet + sizeof(struct ether_header) +
                         sizeof(struct iphdr) + sizeof(struct udphdr));
  /*
      for (int i = 0; i < ETH_ALEN; i++) {
          cout << eh->ether_dhost[i] << endl;
      }

  */
  /* All network ordered messages are multicast.
   * Check ethernet destination is FF:FF:FF:FF:FF:FF,
   * and IP destination is the group multicast address.
   */
  // only process traggic from boa2 now
  // fa:16:3e:f5:8b:83
  if (!(eh->ether_shost[0] == 0xfa && eh->ether_shost[1] == 0x16 &&
        eh->ether_shost[2] == 0x3e && eh->ether_shost[3] == 0xf5 &&
        eh->ether_shost[4] == 0x8b && eh->ether_shost[5] == 0x83)) {
    return false;
  }

  eh->ether_shost[3] = 0xc9;
  eh->ether_shost[4] = 0x64;
  eh->ether_shost[5] = 0x80;
  eh->ether_dhost[0] = MY_DEST_MAC0;
  eh->ether_dhost[1] = MY_DEST_MAC1;
  eh->ether_dhost[2] = MY_DEST_MAC2;
  eh->ether_dhost[3] = MY_DEST_MAC3;
  eh->ether_dhost[4] = MY_DEST_MAC4;
  eh->ether_dhost[5] = MY_DEST_MAC5;
  // Ethertype field
  eh->ether_type = htons(ETH_P_ALL);

  return true;
  /*for (int i = 0; i < ETH_ALEN; i++) {
      if (eh->ether_dhost[i] != 0xFF) {
          return false;
      }
  }
  */
  // cout << destip << endl;
  ((struct sockaddr_in *)&saddr)->sin_addr.s_addr = iph->daddr;
  inet_ntop(AF_INET, &((struct sockaddr_in *)&saddr)->sin_addr, destip,
            sizeof(destip));

  /*
      if (strcmp(destip, this->config->GetGroupAddr().c_str())) {
          return false;
      }
  */
  /* Network ordered packet header format:
   * FRAG_MAGIC(32) | header data len (32) | original udp src (16) |
   * session ID (64) | number of groups (32) |
   * group1 ID (32) | group1 sequence number (64) |
   * group2 ID (32) | group2 sequence number (64) |
   * ...
   */
  /*
      if (*(uint32_t *)datagram != NONFRAG_MAGIC) {
          // Only sequence the packet if it is not
          // fragmented.
          return false;
      }
  */
  datagram += sizeof(uint32_t) + sizeof(uint32_t);  // now points to udp src
  /* Write the original udp src into header */
  *(uint16_t *)datagram = udph->source;

  datagram += sizeof(uint16_t);  // now points to session ID
  *(uint64_t *)datagram = this->sequencer->GetSequencerID();

  datagram += sizeof(uint64_t);  // now points to number of groups
  ngroups = *(uint32_t *)datagram;

  datagram += sizeof(uint32_t);  // now points to group1 ID
  group_bitmap = 0;
  for (int i = 0; i < ngroups; i++) {
    uint32_t groupid = *(uint32_t *)datagram;
    datagram += sizeof(uint32_t);
    *(uint64_t *)datagram = this->sequencer->Increment(groupid);
    datagram += sizeof(uint64_t);
    group_bitmap |= (1 << groupid);
  }

  /* Update udp header src field with the group bitmap.
   * Switches use this bitmap to perform group cast.
   */
  udph->source = htons(group_bitmap);
  udph->check = 0;  // disable udp checksum
  return true;
}

}  // namespace sequencer

int main(int argc, char *argv[]) {
  const char *config_path = nullptr;
  int opt;

  while ((opt = getopt(argc, argv, "c:")) != -1) {
    switch (opt) {
      case 'c':
        config_path = optarg;
        break;

      default:
        fprintf(stderr, "Unknown argument %s\n", argv[optind]);
        break;
    }
  }

  if (config_path == nullptr) {
    fprintf(stderr, "option -c is required\n");
    return 1;
  }

  ifstream config_stream(config_path);
  if (config_stream.fail()) {
    fprintf(stderr, "unable to read configuration file: %s\n", config_path);
    return 1;
  }

  sequencer::Configuration config(config_stream);
  sequencer::Sequencer sequencer(0);
  sequencer::Transport transport(&sequencer, &config);
  transport.Run();

  return 0;
}
