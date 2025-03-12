/**
 * ISA Project - Monitoring of DNS communication
 * @brief Overhead for file entry management
 * @file file_records_mgmt.c
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 16-11-2024
 */

#include "file_records_mgmt.h"

FILE *domainsfile = NULL;
FILE *translationsfile = NULL;
struct domain_name_ll ll = {NULL, NULL};


struct domain_name *_ll_add(char *dname, bool init) {
    struct domain_name *dn = malloc(sizeof(struct domain_name));
    struct domain_name *tmp;
    str_init(&dn->name);
    str_append_stream(&dn->name, dname);
    dn->translation = NULL;
    if (ll.lst) {
        tmp = ll.lst;
        tmp->next = dn;
        ll.lst = dn;
    }
    if (!ll.fst) {
        ll.fst = dn;
        ll.lst = dn;
    }
    dn->next = NULL;
    if (domainsfile && !init) {
        fprintf(domainsfile, "%s\n", dname);
        fflush(domainsfile);
    }
    return dn;
}


struct domain_name *_locate_dname_entry(char *dname) {
    struct domain_name *dn = ll.fst;
    while (dn) {
        if (str_cmp(&dn->name, dname)) {
            break;
        }
        dn = dn->next;
    }
    return dn;
}


void _add_taddr(char *taddr, struct domain_name *dname, bool init) {
    struct translation_name *ptr = dname->translation;
    struct translation_name *prev;
    while (ptr) {
        if (str_cmp(&ptr->name, taddr)) {
            return;
        }
        prev = ptr;
        ptr = ptr->next;
    }
    ptr = malloc(sizeof(struct translation_name));
    ptr->next = NULL;
    str_init(&ptr->name);
    str_append_stream(&ptr->name, taddr);
    if (dname->translation) {
        prev->next = ptr;
    }
    else {
        dname->translation = ptr;
    }
    if (translationsfile && !init) {
        fprintf(translationsfile, "%s %s\n", dname->name.body, taddr);
        fflush(translationsfile);
    }
}


void add_dname_entry(char *dname, bool init) {
    struct domain_name *dn = _locate_dname_entry(dname);
    if (dn) {
        return;
    }
    _ll_add(dname, init);
}


void add_taddr_entry_to_dname(char *taddr, char *dname, bool init) {
    struct domain_name *dn = _locate_dname_entry(dname);
    if (!dn) {
        dn = _ll_add(dname, init);
    }
    _add_taddr(taddr, dn, init);
}


void _parse_tfile() {
    char dname[NS_MAXDNAME + 1];
    char taddr[INET6_ADDRSTRLEN + 2];

    do {
        if (fscanf(translationsfile, "%s %s", dname, taddr) == EOF) {
            break;
        }

        if (taddr[strlen(taddr)] == '\n') {
            taddr[strlen(taddr)] = '\0';
        }

        add_taddr_entry_to_dname(taddr, dname, true);

    } while(true);
}


void _parse_dfile() {
    char dname[NS_MAXDNAME + 2];

    do {
        if (fscanf(domainsfile, "%s", dname) == EOF) {
            break;
        }

        if (dname[strlen(dname)] == '\n') {
            dname[strlen(dname)] = '\0';
        }

        add_dname_entry(dname, true);

    } while (true);
}

bool set_files(string_t *dfile, string_t *tfile) {
    if (dfile->len) {
        domainsfile = fopen(dfile->body, "a+");
        if (domainsfile) {
            rewind(domainsfile);
            _parse_dfile();
        }
        else {
            return false;
        }
    }
    if (tfile->len) {
        translationsfile = fopen(tfile->body, "a+");
        if (translationsfile) {
            rewind(translationsfile);
            _parse_tfile();
        }
        else {
            if (domainsfile) {
                return false;
            }
        }
    }
    return true;
}


void _entries_dtor() {
    struct domain_name *dn_ptr = ll.fst;
    struct domain_name *dn_tmp;
    struct translation_name *tn_ptr;
    struct translation_name *tn_tmp;
    while (dn_ptr) {
        tn_ptr = dn_ptr->translation;
        while(tn_ptr) {
            tn_tmp = tn_ptr->next;
            str_dtor(&tn_ptr->name);
            free(tn_ptr);
            tn_ptr = tn_tmp;
        }
        dn_tmp = dn_ptr->next;
        str_dtor(&dn_ptr->name);
        free(dn_ptr);
        dn_ptr = dn_tmp;
    }
}


void files_teardown() {
    _entries_dtor();

    if (translationsfile) {
        fclose(translationsfile);

    }
    if (domainsfile) {
        fclose(domainsfile);
    }
}
