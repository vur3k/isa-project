/**
 * ISA Project - Monitoring DNS communication
 * @brief Dynamic string
 * @file string_t.h
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 26-09-2024
 * @note repurposed from IFJ Project - IFJ23 language compiler
 */

#ifndef _STRING_T_H
#define _STRING_T_H


#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#define STRING_ALLOC_CHUNK 128


/**
 * @brief Structure to represent strings
 * @struct string_t
 */
typedef struct {
    char *body; // The contents of the string
    uint16_t len;    // String length
    uint16_t cap;    // Allocated string capacity
} string_t;


/**
 * @brief Inicialization of a string
 * @param str Pointer to a string structure whose memory will be allocated
 */
void str_init(string_t *str);


/**
 * @brief Is string empty
 * @param str Pointer to a string which will be examined
 * @return true if string length is 0, false otherwise
 */
bool str_is_empty(string_t *str);


/**
 * @brief Reallocation of a string
 * @param str Pointer to a string whose memory will be reallocated
 */
void str_realloc(string_t *str);


/**
 * @brief Append a character to a string
 * @param str Pointer to a string that will be extended
 * @param c Character to be appended
 */
void str_append_char(string_t *str, char c);


/**
 * @brief Append stream of characters to a string
 * @param str Pointer to a string that will be extended
 * @param stream Stream of characters to be appended
 */
void str_append_stream(string_t *str, char *stream);


/**
 * @brief String destructor
 * @param str Pointer to a string whose allocated memory will be freed
 */
void str_dtor(string_t *str);


/**
 * @brief Clear contents of a string
 * @param str Pointer to a string whose allocated memory will be erased
 * @note len will be set to 0, cap to 128
 */
void str_clear(string_t *str);


/**
 * @brief Compare a string to a static stream of chars
 * @param str Pointer to a string to compare
 * @param stream Stream of chars to compare
 * @return true if the strings are identical, false otherwise
 */
bool str_cmp(string_t *str, const char *stream);

#endif
