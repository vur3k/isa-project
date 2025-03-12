/**
 * ISA Project - Monitoring of DNS communication
 * @brief DNS message traffic monitor
 * @file dns-monitor.h
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 16-11-2024
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
#include <pcap/sll.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include "string_t.h"
#include "arg_parser.h"
#include "file_records_mgmt.h"

/**
 * @brief Structure to represent header of UDP Datagram
 * @note It is hardcoded due to parity issues to build the project on both refference servers
 */
struct udp_hdr {
    uint16_t src_port;  // Source port
    uint16_t dst_port;  // Destination port
    uint16_t length;    // Length of the packet
    uint16_t checksum;  // Sum to check the integrity of the packet
};

/**
 * @brief Print help-string
 * @param progname The name of the program
 */
void print_help(char *progname);

/**
 * @brief Interrupt handling routine
 */
void interrupt_handler();

/**
 * @brief Print timestamp
 * @param ts Structure holding the timestamp data
 */
void print_timestamp(struct timeval ts);

/**
 * @brief Print IP addresses
 * @param src Source ip address
 * @param dst Destination ip address
 */
void print_addr(char *src, char *dst);

/**
 * @brief Print UDP protocol data
 * @param hdr UDP header
 */
void print_udp_port(struct udp_hdr *hdr);

/**
 * @brief Print information from NS message
 * @param msg NS message
 */
void print_ns_info(ns_msg *msg);

/**
 * @brief Get NS typestring
 * @param type Numeric value of NS type
 */
char *get_type(uint16_t type);

/**
 * @brief NS Record - Question processing routine
 * @param rr NS record
 */
void process_ns_query(ns_rr *rr);

/**
 * @brief NS Record - Answer processing routine
 * @param rr NS record
 * @param msg NS message
 * @param store_taddr Whether the translation of DName will be stored to external file
*/
void process_ns_answer(ns_rr *rr, ns_msg *msg, bool store_taddr);

/**
 * @brief Print info from captured packet
 * @param pkt Captured packet
 * @param ns_handle NS message
 * @param src Source IP address
 * @param dst Destination IP address
 * @param proto_hdr Transport protocol header
 */
void print_packet_info(const struct pcap_pkthdr *pkt, ns_msg *ns_handle, char *src, char *dst, const uint8_t *proto_hdr);

/**
 * @brief Callback function to process captured packets
 * @param user
 * @param pkt Header of captured packet
 * @param buff Captured data
 */
void callback(uint8_t *user, const struct pcap_pkthdr *pkt, const uint8_t *buff);

#endif
