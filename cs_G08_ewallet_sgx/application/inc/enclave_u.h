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

#ifndef OCALL_SAVE_WALLET_DEFINED__
#define OCALL_SAVE_WALLET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_save_wallet, (uint8_t* wallet, size_t wallet_size));
#endif
#ifndef OCALL_LOAD_WALLET_DEFINED__
#define OCALL_LOAD_WALLET_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_load_wallet, (uint8_t* wallet, size_t wallet_size));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t ecall_generate_password(sgx_enclave_id_t eid, int* retval, char* p_value, int p_length);
sgx_status_t ecall_create_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_show_wallet(sgx_enclave_id_t eid, int* retval, const char* master_password);
sgx_status_t ecall_change_master_password(sgx_enclave_id_t eid, int* retval, const char* old_password, const char* new_password);
sgx_status_t ecall_add_item(sgx_enclave_id_t eid, int* retval, const char* master_password, const uint8_t* item, size_t item_size);
sgx_status_t ecall_remove_item(sgx_enclave_id_t eid, int* retval, const char* master_password, int index);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
