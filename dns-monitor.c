/**
 * ISA Project - Monitoring of DNS communication
 * @brief DNS message traffic monitor
 * @file dns-monitor.c
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 16-11-2024
 */

#include "dns-monitor.h"

#define EXIT_TERMINATED 130
struct args args;


void print_help(char *progname) {
    printf("Usage: %s (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>] [-h]\n"
           "Options:\n"
           "         -i <interface>        : listen for DNS messages on <interface>\n"
           "         -p <pcapfile>         : process DNS messages from <pcapfile>\n"
           "         -v                    : printout verbose output\n"
           "         -d <domainsfile>      : store received domain names into <domainsfile>\n"
           "         -t <translationsfile> : store received translations of domain names into <translationsfile>\n"
           "         -h                    : print this message\n", progname
    );
}


void interrupt_handler() {
    files_teardown();
    pcap_breakloop(args.handle);
    args_dtor(&args);
    exit(EXIT_TERMINATED);
}


void print_timestamp(struct timeval ts) {
    time_t t = ts.tv_sec;
    struct tm *tm = localtime(&t);
    printf(args.verbose ? "Timestamp: %d-%02d-%02d %02d:%02d:%02d\n" : "%d-%02d-%02d %02d:%02d:%02d ",
        tm->tm_year + 1900,
        tm->tm_mon + 1,
        tm->tm_mday,
        tm->tm_hour,
        tm->tm_min,
        tm->tm_sec
    );
}


void print_addr(char *src, char *dst) {
    printf(args.verbose ? "SrcIP: %s\nDstIP: %s\n" : "%s -> %s ", src, dst);
}


void print_udp_port(struct udp_hdr *hdr) {
    printf("SrcPort: UDP/%d\nDstPort: UDP/%d\n", ntohs(hdr->src_port), ntohs(hdr->dst_port));
}


void print_ns_info(ns_msg *msg) {
    if (args.verbose) {
        printf("Identifier: 0x%04x\nFlags: QR=%d, OPCODE=%d, AA=%d, TC=%d, RD=%d, RA=%d, AD=%d, CD=%d, RCODE=%d\n",
            ns_msg_id(*msg),
            ns_msg_getflag(*msg, ns_f_qr),
            ns_msg_getflag(*msg, ns_f_opcode),
            ns_msg_getflag(*msg, ns_f_aa),
            ns_msg_getflag(*msg, ns_f_tc),
            ns_msg_getflag(*msg, ns_f_rd),
            ns_msg_getflag(*msg, ns_f_ra),
            ns_msg_getflag(*msg, ns_f_ad),
            ns_msg_getflag(*msg, ns_f_cd),
            ns_msg_getflag(*msg, ns_f_rcode)
        );
    }
    else {
        printf("(%c %d/%d/%d/%d)\n",
            ns_msg_getflag(*msg, ns_f_qr) ? 'R' : 'Q',
            ns_msg_count(*msg, ns_s_qd),
            ns_msg_count(*msg, ns_s_an),
            ns_msg_count(*msg, ns_s_ns),
            ns_msg_count(*msg, ns_s_ar)
        );
    }
}


char *get_type(uint16_t type) {
    switch(type){
        case T_A:
            return "A";
        case T_AAAA:
            return "AAAA";
        case T_NS:
            return "NS";
        case T_MX:
            return "MX";
        case T_SOA:
            return "SOA";
        case T_CNAME:
            return "CNAME";
        case T_SRV:
            return "SRV";
        default:
            return NULL;
    }
}


void process_ns_query(ns_rr *rr) {
    char *type_str = get_type(ns_rr_type(*rr));
    char *dname = ns_rr_name(*rr);
    if (type_str) {
        add_dname_entry(dname, false);
        if (args.verbose) printf("%s. IN %s\n", dname, type_str);
    }
}


void process_ns_answer(ns_rr *rr, ns_msg *msg, bool store_taddr) {
    uint16_t type = ns_rr_type(*rr);
    char *type_str = get_type(type);
    char rdata[NS_MAXDNAME];
    char mdata[NS_MAXDNAME];
    uint16_t mx_prio;
    uint16_t *srv_vals; // {PRIORITY, WEIGHT, PORT}
    uint32_t *soa_vals; // {SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM}
    int rlen, mlen;
    char *dname;

    if (type_str) {
        dname = ns_rr_name(*rr);
        add_dname_entry(dname, false);
        switch (type) {
            case T_A:
                inet_ntop(AF_INET, ns_rr_rdata(*rr), rdata, NS_MAXDNAME);
                if (store_taddr) {
                    add_taddr_entry_to_dname(rdata, dname, false);
                }
                break;
            case T_AAAA:
                inet_ntop(AF_INET6, ns_rr_rdata(*rr), rdata, NS_MAXDNAME);
                if (store_taddr) {
                    add_taddr_entry_to_dname(rdata, dname, false);
                }
                break;
            case T_CNAME:
            case T_NS:
                ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg) , ns_rr_rdata(*rr), rdata, sizeof(rdata));
                add_dname_entry(rdata, false);
                break;
            case T_MX:
                ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg) , ns_rr_rdata(*rr) + sizeof(uint16_t), rdata, sizeof(rdata));
                mx_prio = ntohs(*(uint16_t *)ns_rr_rdata(*rr));
                break;
            case T_SRV:
                ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg), ns_rr_rdata(*rr) + 3*sizeof(uint16_t), rdata, sizeof(rdata));
                srv_vals = (uint16_t *)(ns_rr_rdata(*rr));
                break;
            case T_SOA:
                rlen = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg), ns_rr_rdata(*rr), rdata, sizeof(rdata));
                mlen = ns_name_uncompress(ns_msg_base(*msg), ns_msg_end(*msg), ns_rr_rdata(*rr) + rlen, mdata, sizeof(mdata));
                soa_vals = (uint32_t *)(ns_rr_rdata(*rr) +  rlen + mlen);
                break;
            default:
                break;
        }
        if (args.verbose) {
            switch(type) {
                case T_SOA:
                    printf("%s. %u IN %s %s. %s. %u %u %u %u %u\n",
                        dname,
                        ns_rr_ttl(*rr),
                        type_str,
                        rdata,
                        mdata,
                        ntohl(soa_vals[0]),
                        ntohl(soa_vals[1]),
                        ntohl(soa_vals[2]),
                        ntohl(soa_vals[3]),
                        ntohl(soa_vals[4])
                    );
                    break;
                case T_MX:
                    printf("%s. %u IN %s %u %s.\n",
                        dname,
                        ns_rr_ttl(*rr),
                        type_str,
                        mx_prio,
                        rdata
                    );
                    break;
                case T_SRV:
                    printf("%s. %u IN %s %u %u %u %s.\n",
                        dname,
                        ns_rr_ttl(*rr),
                        type_str,
                        ntohs(srv_vals[0]),
                        ntohs(srv_vals[1]),
                        ntohs(srv_vals[2]),
                        rdata
                    );
                    break;
                default:
                    printf("%s. %u IN %s %s%s\n",
                        dname,
                        ns_rr_ttl(*rr),
                        type_str,
                        rdata,
                        (type == T_A || type == T_AAAA) ? "" : "."
                    );
                    break;
            }
        }
    }
}


void print_packet_info(const struct pcap_pkthdr *pkt, ns_msg *ns_handle, char *src, char *dst, const uint8_t *proto_hdr) {
    print_timestamp(pkt->ts);
    print_addr(src, dst);
    if (args.verbose) {
        print_udp_port((struct udp_hdr *) proto_hdr);
    }

    print_ns_info(ns_handle);
    ns_rr ns_record;

    if (args.verbose || args.domainsfile.len || args.translationsfile.len) {
        if (ns_msg_count(*ns_handle, ns_s_qd)) {
            if (args.verbose) printf("\n[Question Section]\n");
            for (int i = 0; i < ns_msg_count(*ns_handle, ns_s_qd); i++) {
                ns_parserr(ns_handle, ns_s_qd, i, &ns_record);
                process_ns_query(&ns_record);
            }
        }
        if (ns_msg_count(*ns_handle, ns_s_an)) {
            if (args.verbose) printf("\n[Answer Section]\n");
            for (int i = 0; i < ns_msg_count(*ns_handle, ns_s_an); i++) {
                ns_parserr(ns_handle, ns_s_an, i, &ns_record);
                process_ns_answer(&ns_record, ns_handle, true);
            }
        }
        if (ns_msg_count(*ns_handle, ns_s_ns)) {
            if (args.verbose) printf("\n[Authority Section]\n");
            for (int i = 0; i < ns_msg_count(*ns_handle, ns_s_ns); i++) {
                ns_parserr(ns_handle, ns_s_ns, i, &ns_record);
                process_ns_answer(&ns_record, ns_handle, false);
            }
        }
        if (ns_msg_count(*ns_handle, ns_s_ar)) {
            if (args.verbose) printf("\n[Additional Section]\n");
            for (int i = 0; i < ns_msg_count(*ns_handle, ns_s_ar); i++) {
                ns_parserr(ns_handle, ns_s_ar, i, &ns_record);
                process_ns_answer(&ns_record, ns_handle, true);
            }
        }
        if (args.verbose) printf("====================\n");
    }
}


void callback(uint8_t *user, const struct pcap_pkthdr *pkt, const uint8_t *buff) {
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);

    struct ether_header *eth_hdr = NULL;
    struct sll_header *sll_hdr = NULL;      // if we're listening on device such as 'any' we'll receive this
                                            // kind of packet instead of the ethernet one
    uint16_t hdr_type;

    if (args.d_link == DLT_EN10MB) {
        eth_hdr = (struct ether_header *) buff;
        hdr_type = ntohs(eth_hdr->ether_type);
    }
    else if (args.d_link == DLT_LINUX_SLL) {
        sll_hdr = (struct sll_header *) buff;
        hdr_type = ntohs(sll_hdr->sll_protocol);
    }
    else {
        fprintf(stderr, "Error: Interface '%s' uses unsupported type of datalink\n", args.interface.body);
        files_teardown();
        pcap_breakloop(args.handle);
        args_dtor(&args);
        exit(EXIT_FAILURE);
    }
    uint16_t ip_hdr_len = 0;
    char dst[INET6_ADDRSTRLEN + 1];
    char src[INET6_ADDRSTRLEN + 1];
    struct ip *ip_hdr = NULL;
    struct ip6_hdr *ip6_hdr = NULL;
    uint16_t protocol;
    const uint8_t *proto_hdr;

    if (hdr_type == ETHERTYPE_IP) {
        if (eth_hdr) {
            ip_hdr = (struct ip *) (buff + sizeof(struct ether_header));
        }
        else if (sll_hdr) {
            ip_hdr = (struct ip *) (buff + sizeof(struct sll_header));
        }
        ip_hdr_len = ip_hdr->ip_hl << 2;
        inet_ntop(AF_INET, &ip_hdr->ip_src, src, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_hdr->ip_dst, dst, INET_ADDRSTRLEN);
    }
    else if (hdr_type == ETHERTYPE_IPV6) {
        if (eth_hdr) {
            ip6_hdr = (struct ip6_hdr *) (buff + sizeof(struct ether_header));
        }
        else if (sll_hdr) {
            ip6_hdr = (struct ip6_hdr *) (buff + sizeof(struct sll_header));
        }
        ip_hdr_len = sizeof(struct ip6_hdr);
        inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst, INET6_ADDRSTRLEN);
    }

    if (eth_hdr) {
        proto_hdr = buff + sizeof(struct ether_header) + ip_hdr_len;
    }
    else if (sll_hdr) {
        proto_hdr = buff + sizeof(struct sll_header) + ip_hdr_len;
    }

    if (ip_hdr) {
        protocol = ip_hdr->ip_p;
    }
    else if (ip6_hdr) {
        struct ip6_rthdr *ip6_rthdr = NULL;
        struct ip6_rthdr0 *ip6_rthdr0 = NULL;
        struct ip6_hbh *ip6_hbh = NULL;
        struct ip6_dest *ip6_dest = NULL;
        protocol = ip6_hdr->ip6_nxt;

        while (true) {
            switch(protocol) {
                case IPPROTO_ROUTING:
                    ip6_rthdr = (struct ip6_rthdr *) proto_hdr;
                    if (!ip6_rthdr->ip6r_type) {
                        ip6_rthdr0 = (struct ip6_rthdr0 *) proto_hdr;
                        protocol = ip6_rthdr0->ip6r0_nxt;
                        proto_hdr += (sizeof(struct ip6_rthdr0) + (ip6_rthdr0->ip6r0_len << 3));
                    }
                    else {
                        protocol = ip6_rthdr->ip6r_nxt;
                        proto_hdr += (sizeof(struct ip6_rthdr) + (ip6_rthdr->ip6r_len << 3));
                    }
                    break;
                case IPPROTO_HOPOPTS:
                    ip6_hbh = (struct ip6_hbh *) proto_hdr;
                    protocol = ip6_hbh->ip6h_nxt;
                    proto_hdr += (sizeof(struct ip6_hbh) + (ip6_hbh->ip6h_len << 3));
                    break;
                case IPPROTO_DSTOPTS:
                    ip6_dest = (struct ip6_dest *) proto_hdr;
                    protocol = ip6_dest->ip6d_nxt;
                    proto_hdr += (sizeof(struct ip6_dest) + (ip6_dest->ip6d_len << 3));
                    break;
                case IPPROTO_FRAGMENT:
                    protocol = ((struct ip6_frag *) proto_hdr)->ip6f_nxt;
                    proto_hdr += sizeof(struct ip6_frag);
                    break;
                case IPPROTO_IPV6:
                    protocol = ((struct ip6_hdr *) proto_hdr)->ip6_nxt;
                    inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src, INET6_ADDRSTRLEN);
                    inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst, INET6_ADDRSTRLEN);
                    proto_hdr += ip_hdr_len;
                    break;
                default:
                    break;
            }
            if (protocol == IPPROTO_UDP) {
                break;
            }
            else if (protocol == IPPROTO_ROUTING || protocol == IPPROTO_HOPOPTS || protocol == IPPROTO_DSTOPTS || protocol == IPPROTO_FRAGMENT || protocol == IPPROTO_IPV6) {
                continue;
            }
            else {
                return;
            }
        }
    }
    const uint8_t *dns = proto_hdr + sizeof(struct udp_hdr);
    uint16_t payload_len = ntohs(((struct udp_hdr *) proto_hdr)->length) - sizeof(struct udp_hdr);

    ns_msg ns_handle;
    ns_initparse(dns, payload_len, &ns_handle);

    print_packet_info(pkt, &ns_handle, src, dst, proto_hdr);
    return;
}


int main (int argc, char **argv) {
    signal(SIGINT, interrupt_handler);
    signal(SIGTERM, interrupt_handler);
    signal(SIGQUIT, interrupt_handler);
    args_init(&args);
    parse_args(argc, argv, &args);
    if (args.help) {
        print_help(argv[0]);
        args_dtor(&args);
        return EXIT_SUCCESS;
    }
    char err_buf[PCAP_ERRBUF_SIZE + 1];
    bpf_u_int32 ip, mask = PCAP_NETMASK_UNKNOWN;

    if (!str_is_empty(&args.interface)) { // process device listen
        pcap_lookupnet(args.interface.body, &ip, &mask, err_buf);
        args.handle = pcap_open_live(args.interface.body, BUFSIZ, 1, 1000, err_buf);
    }
    else if (!str_is_empty(&args.pcapfile)) { // process pcapfile parsing
        args.handle = pcap_open_offline(args.pcapfile.body, err_buf);
    }
    else {
        args_dtor(&args);
        fprintf(stderr, ERR_INVALID_USAGE);
        return EXIT_FAILURE;
    }

    if (!args.handle) {
        fprintf(stderr, "Error: Couldn't open a device for capture: %s\n", err_buf);
        args_dtor(&args);
        return EXIT_FAILURE;
    }

    if (pcap_compile(args.handle, &args.bpf, "udp port 53", 1, mask) == PCAP_ERROR) {
        fprintf(stderr, "Error: Filter compilation failed:\n");
        args_dtor(&args);
        return EXIT_FAILURE;
    }

    if (pcap_setfilter(args.handle, &args.bpf) == PCAP_ERROR) {
        fprintf(stderr, "Error: Filter setup failed\n");
        args_dtor(&args);
        return EXIT_FAILURE;
    }

    if (!set_files(&args.domainsfile, &args.translationsfile)) {
        fprintf(stderr, "Error: Files couldn't be opened\n");
        args_dtor(&args);
        files_teardown();
        return EXIT_FAILURE;
    }

    args.d_link = pcap_datalink(args.handle);
    pcap_loop(args.handle, 0, callback, NULL);

    // processing

    args_dtor(&args);

    files_teardown();

    return EXIT_SUCCESS;
}
