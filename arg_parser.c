/**
 * ISA Project - Monitoring of DNS communication
 * @brief Argument parser
 * @file arg_parser.c
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 16-11-2024
 */

#include "arg_parser.h"

/**
 * @brief Macro to process arguments
 * @link https://cfengine.com/blog/2021/optional-arguments-with-getopt-long/
 * @author Lars Erik Wik
 * @copyright Copyright 2021 by Lars Erik Wik. All rights reserved. This macro is released under the GNU GPL
 *
 * since getopt does not terminate on passing invalid args, i had to work my way around it
 */
#define ARGUMENT_IS_PRESENT \
    ((optarg == NULL && optind < argc && argv[optind][0] != '-') \
     ? (bool) (optarg = argv[optind++]) \
     : (optarg != NULL))


void args_init(struct args *args) {
    str_init(&args->interface);
    str_init(&args->pcapfile);
    str_init(&args->domainsfile);
    str_init(&args->translationsfile);
    args->handle = NULL;
}

void args_dtor(struct args *args) {
    str_dtor(&args->interface);
    str_dtor(&args->pcapfile);
    str_dtor(&args->domainsfile);
    str_dtor(&args->translationsfile);
    if (args->handle) {
        pcap_close(args->handle);
    }
    pcap_freecode(&args->bpf);
}


void parse_args(int argc, char **argv, struct args *args) {
    int8_t opt;
    bool err = false;
    while ((opt = getopt(argc, argv, "i::p::vd::t::h")) != -1) {
        switch(opt) {
            case 'i':
                if (str_is_empty(&args->interface) && str_is_empty(&args->pcapfile) && ARGUMENT_IS_PRESENT) {
                    str_append_stream(&args->interface, optarg);
                }
                else {
                    err = true;
                }
                break;
            case 'p':
                if (str_is_empty(&args->interface) && str_is_empty(&args->pcapfile) && ARGUMENT_IS_PRESENT) {
                    str_append_stream(&args->pcapfile, optarg);
                }
                else {
                    err = true;
                }
                break;
            case 'v':
                args->verbose = true;
                break;
            case 'd':
                if (str_is_empty(&args->domainsfile) && ARGUMENT_IS_PRESENT) {
                    str_append_stream(&args->domainsfile, optarg);
                }
                else {
                    err = true;
                }
                break;
            case 't':
                if (str_is_empty(&args->translationsfile) && ARGUMENT_IS_PRESENT) {
                    str_append_stream(&args->translationsfile, optarg);
                }
                else {
                    err = true;
                }
                break;
            case 'h':
                args->help = true;
                return;
        }
        if (err) {
            fprintf(stderr, ERR_INVALID_USAGE);
            args_dtor(args);
            exit(EXIT_FAILURE);
        }
    }
}
