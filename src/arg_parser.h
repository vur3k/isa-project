/**
 * ISA Project - Monitoring of DNS communication
 * @brief Argument parser
 * @file arg_parser.h
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 16-11-2024
 */

#ifndef _ARG_PARSER_H
#define _ARG_PARSER_H

#include <stdlib.h>
#include <stdbool.h>

#include <pcap.h>
#include <getopt.h>
#include "string_t.h"

#define ERR_INVALID_USAGE "Error: Invalid usage of arguments; try '%s -h'\n", argv[0]

/**
 * @brief Structure to hold the passed data from prompt
 * @struct args
 */
struct args {
    string_t interface; // Interface which will be used for the capture
    string_t pcapfile; // Pcapfile which will be read
    bool verbose;   // Whether the output should be verbose
    string_t domainsfile;   // Name of the file which will be used to store the domain names
    string_t translationsfile; // Name of the file which will be used to store the translations of the domain names
    bool help;  // Whether the help message should be printed
    pcap_t *handle; // Handle of the capture device
    struct bpf_program bpf; // Compiled packet filter
    int d_link; // Datalink type of used interface
};

/**
 * @brief Initialize structure for argument parsing
 * @param args Structure that will be initialized
 */
void args_init(struct args *args);

/**
 * @brief Deallocator of inner dynamic memory
 * @param args Structure which dynamic resources will be freed
 */
void args_dtor(struct args *args);

/**
 * @brief Parse the arguments from prompt
 * @param argc Count of arguments
 * @param argv Vector of arguments
 * @param args Structure that will hold the obtained data
 */
void parse_args(int argc, char **argv, struct args *args);

#endif
