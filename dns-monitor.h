/**
 * ISA Project - Monitoring DNS communication
 * @brief DNS message traffic monitor
 * @file dns-monitor.h
 * 
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 26-09-2024
 */

#ifndef _DNS_MONITOR_H
#define _DNS_MONITOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>

#include <signal.h>
#include <time.h>

#include <pcap.h>
#include <resolv.h>

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "string_t.h"
#include "arg_parser.h"
#include "file_records_mgmt.h"

struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcnt;
    uint16_t ancnt;
    uint16_t nscnt;
    uint16_t arcnt;
};

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

#endif
