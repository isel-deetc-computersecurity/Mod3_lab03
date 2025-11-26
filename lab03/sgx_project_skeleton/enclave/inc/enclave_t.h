#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int ecall_get_rand_prime_sealed(int size, unsigned char* prime_sealed);
int ecall_get_sealed_data(int size, unsigned char* old_prime_sealed, unsigned char* new_prime_sealed);
int ecall_get_size(void);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
