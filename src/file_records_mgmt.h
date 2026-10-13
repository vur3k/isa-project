/**
 * ISA Project - Monitoring of DNS communication
 * @brief Overhead for file entry management
 * @file file_records_mgmt.h
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 16-11-2024
 */

#ifndef _FILE_RECORDS_MGMT
#define _FILE_RECORDS_MGMT

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <resolv.h>
#include "string_t.h"

/**
 * @brief Structure to represent domain name translation entries
 * @struct translation_name
 */
struct translation_name {
    string_t name;  // Translation of the domain name
    struct translation_name *next;  // Pointer to a next entry
};

/**
 * @brief Structure to represent domain name entries
 * @struct domain_name
 */
struct domain_name {
    string_t name;  // Domain name
    struct domain_name *next;   // Pointer to a next entry
    struct translation_name *translation;   // Pointer to a linked list of translations
};

/**
 * @brief Structure to hold the domain name entries
 * @struct domain_name_ll
 */
struct domain_name_ll {
    struct domain_name *fst;    // Pointer to the first element of the linked list
    struct domain_name *lst;    // Pointer to the last element of the linked list
};

/**
 * @brief Store domain name entry
 * @param dname The domain name
 * @param init Whether the function is called during initializing routine
 */
void add_dname_entry(char *dname, bool init);

/**
 * @brief Store translation of a domain name
 * @param taddr The translation of a domain name
 * @param dname The domain name
 * @param init Whether the function is called during initializing routine
 */
void add_taddr_entry_to_dname(char *taddr, char *dname, bool init);

/**
 * @brief Set the output files
 * @param dfile The name of the file in which the domain names will be stored
 * @param tfile The name of the file in which the translations of the domain names will be stored
 */
bool set_files(string_t *dfile, string_t *tfile);

/**
 * @brief Close opened files
 */
void files_teardown();

// #################################################################################################
// Functions starting with '_' are inner functions that should not be called outside of this library
// and should be considered as private functions.

/**
 * @brief Add a domain name into linked list
 * @param dname The domain name
 * @param init Whether the function is called during initializing routine
 * @return Pointer to the newly allocated structure
 * @note Inner library function, should not be called outside of the library routines
 */
struct domain_name *_ll_add(char *dname, bool init);

/**
 * @brief Find domain name entry in linked list
 * @param dname The domain name
 * @return Pointer to the corresponding structure or NULL if not present
 * @note Inner library function, should not be called outside of the library routines
 */
struct domain_name *_locate_dname_entry(char *dname);

/**
 * @brief Add a translation address to a given domain name
 * @param taddr The translation of a domain name
 * @param dname The domain name
 * @param init Whether the function is called during initializing routine
 * @note Inner library function, should not be called outside of the library routines
 */
void _add_taddr(char *taddr, struct domain_name *dname, bool init);

/**
 * @brief Parse the file containing translations of the domain names
 * @note Inner library function, should not be called outside of the library routines
 */
void _parse_tfile();

/**
 * @brief Parse the file containing the domain names
 * @note Inner library function, should not be called outside of the library routines
 */
void _parse_dfile();

/**
 * @brief Deallocator of the linked list structure
 * @note Inner library function, should not be called outside of the library routines
 */
void _entries_dtor();

#endif
