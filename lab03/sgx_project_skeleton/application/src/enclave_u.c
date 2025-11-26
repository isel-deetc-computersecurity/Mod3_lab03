#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_get_rand_prime_sealed_t {
	int ms_retval;
	int ms_size;
	unsigned char* ms_prime_sealed;
} ms_ecall_get_rand_prime_sealed_t;

typedef struct ms_ecall_get_sealed_data_t {
	int ms_retval;
	int ms_size;
	unsigned char* ms_old_prime_sealed;
	unsigned char* ms_new_prime_sealed;
} ms_ecall_get_sealed_data_t;

typedef struct ms_ecall_get_size_t {
	int ms_retval;
} ms_ecall_get_size_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_get_rand_prime_sealed(sgx_enclave_id_t eid, int* retval, int size, unsigned char* prime_sealed)
{
	sgx_status_t status;
	ms_ecall_get_rand_prime_sealed_t ms;
	ms.ms_size = size;
	ms.ms_prime_sealed = prime_sealed;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_sealed_data(sgx_enclave_id_t eid, int* retval, int size, unsigned char* old_prime_sealed, unsigned char* new_prime_sealed)
{
	sgx_status_t status;
	ms_ecall_get_sealed_data_t ms;
	ms.ms_size = size;
	ms.ms_old_prime_sealed = old_prime_sealed;
	ms.ms_new_prime_sealed = new_prime_sealed;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t ecall_get_size(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_ecall_get_size_t ms;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

