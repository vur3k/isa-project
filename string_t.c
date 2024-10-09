/**
 * ISA Project - Monitoring DNS communication
 * @brief Dynamic string
 * @file string_t.c
 *
 * @author Vaclav Pribyl <xpriby22@stud.fit.vutbr.cz>
 * @date 26-09-2024
 * @note repurposed from IFJ Project - IFJ23 language compiler
 */

#include "string_t.h"


void str_init(string_t *str) {
    str->body = calloc(STRING_ALLOC_CHUNK, sizeof(char));
    str->len = 0;
    str->cap = STRING_ALLOC_CHUNK - 1;
}


bool str_is_empty(string_t *str) {
    return str->len == 0;
}


void str_realloc(string_t *str) {
    char *tmp = realloc(str->body, sizeof(char) * (str->cap + STRING_ALLOC_CHUNK));
    if (!tmp) {
        str_dtor(str);
    }
    str->body = tmp;
    str->cap += STRING_ALLOC_CHUNK;
}


void str_append_char(string_t *str, char c) {
    if (str->cap < str->len + 1) {
        str_realloc(str);
    }
    str->body[str->len++] = c;
    str->body[str->len] = '\0';
}


void str_append_stream(string_t *str, char *stream) {
    if (stream) {
        for (int i = 0; stream[i] != '\0'; i++) {
            str_append_char(str, stream[i]);
        }
    }
}


void str_dtor(string_t *str) {
    free(str->body);
    str->cap = 0;
    str->len = 0;
    str->body = NULL;
}


void str_clear(string_t *str) {
    str_dtor(str);
    str_init(str);
}


bool str_cmp(string_t *str, const char *stream) {
    for (int pos = 0; str->body[pos] != '\0' || stream[pos] != '\0'; pos++) {
        if (str->body[pos] != stream[pos]) {
            return false;
        }
    }
    return true;
}
