/* Valgrind/Memcheck taint shim for the constant-time leak detector.
 *
 * ct_poison marks a secret buffer "undefined" (uninitialised) to Memcheck;
 * ct_unpoison marks a buffer "defined" again. After poisoning the secret and
 * running a routine, Memcheck reports any conditional branch or memory index
 * that depends on the secret - a data-dependent access, i.e. a constant-time
 * violation. Uses the official client-request macros so no inline asm is
 * hand-written.
 *
 * Build (in WSL2, needs the valgrind dev headers):
 *   gcc -O2 -c ct_poison.c -o ct_poison.o
 */

#include <valgrind/memcheck.h>
#include <stddef.h>

void ct_poison(void *p, size_t n)
{
    (void) VALGRIND_MAKE_MEM_UNDEFINED(p, n);
}

void ct_unpoison(void *p, size_t n)
{
    (void) VALGRIND_MAKE_MEM_DEFINED(p, n);
}
