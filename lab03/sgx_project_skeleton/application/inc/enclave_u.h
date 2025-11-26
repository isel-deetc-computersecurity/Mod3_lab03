#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t ecall_get_rand_prime_sealed(sgx_enclave_id_t eid, int* retval, int size, unsigned char* prime_sealed);
sgx_status_t ecall_get_sealed_data(sgx_enclave_id_t eid, int* retval, int size, unsigned char* old_prime_sealed, unsigned char* new_prime_sealed);
sgx_status_t ecall_get_size(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
