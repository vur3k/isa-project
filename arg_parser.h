/**
 * ISA Project - Monitoring DNS communication
 * @brief Argument parser
 * @file arg_parser.h
 * 
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 25-09-2024
 */

#ifndef _ARG_PARSER_H
#define _ARG_PARSER_H

#include <stdlib.h>
#include <stdbool.h>

#include <pcap.h>
#include <getopt.h>
#include "string_t.h"

#define ERR_INVALID_USAGE "Error: Invalid usage of arguments; try '%s -h'\n", argv[0]

struct args {
    string_t interface;
    string_t pcapfile;
    bool verbose;
    string_t domainsfile;
    string_t translationsfile;
    bool help;
    pcap_t *handle;
    struct bpf_program bpf;
};

void args_init(struct args *args);

void args_dtor(struct args *args);

void parse_args(int argc, char **argv, struct args *args);

#endif
