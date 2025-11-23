#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_get_rand_t {
	int ms_size;
	unsigned char* ms_buf;
} ms_ecall_get_rand_t;

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_enclave = {
	0,
	{ NULL },
};
sgx_status_t ecall_get_rand(sgx_enclave_id_t eid, int size, unsigned char* buf)
{
	sgx_status_t status;
	ms_ecall_get_rand_t ms;
	ms.ms_size = size;
	ms.ms_buf = buf;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

