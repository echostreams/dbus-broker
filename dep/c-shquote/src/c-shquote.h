#pragma once

/**
 * POSIX Shell Compatible Argument Parser
 *
 * This library provides a argument parsing API, that is fully implemented in
 * ISO-C11 and has no external dependencies.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

enum {
        _C_SHQUOTE_E_SUCCESS,

        C_SHQUOTE_E_NO_SPACE,
        C_SHQUOTE_E_BAD_QUOTING,
        C_SHQUOTE_E_EOF,
        C_SHQUOTE_E_CONTAINS_NULL,

        _C_SHQUOTE_E_N,
};

int c_shquote_quote(char **outp,
                    size_t *n_outp,
                    const char *in,
                    size_t n_in);
int c_shquote_unquote(char **outp,
                      size_t *n_outp,
                      const char *in,
                      size_t n_in);
int c_shquote_parse_next(char **outp,
                         size_t *n_outp,
                         const char **inp,
                         size_t *n_inp);
int c_shquote_parse_argv(char ***argvp,
                         size_t *argcp,
                         const char *in,
                         size_t n_in);

#ifdef __cplusplus
}
#endif
