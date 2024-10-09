#ifndef _FILE_RECORDS_MGMT
#define _FILE_RECORDS_MGMT

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <resolv.h>
#include <netinet/ip6.h>
#include "string_t.h"

struct translation_name {
    string_t name;
    struct translation_name *next;
};

struct domain_name {
    string_t name;
    struct domain_name *next;
    struct translation_name *translation;
};

struct domain_name_ll {
    struct domain_name *fst;
    struct domain_name *lst;
};

bool set_files(string_t *dfile, string_t *tfile);

void files_teardown();

void add_taddr_entry_to_dname(char *taddr, char *dname, bool init);

void add_dname_entry(char *dname, bool init);

#endif