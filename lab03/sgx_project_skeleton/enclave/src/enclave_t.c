#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_get_rand_prime_sealed(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_rand_prime_sealed_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_rand_prime_sealed_t* ms = SGX_CAST(ms_ecall_get_rand_prime_sealed_t*, pms);
	ms_ecall_get_rand_prime_sealed_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_rand_prime_sealed_t), ms, sizeof(ms_ecall_get_rand_prime_sealed_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_prime_sealed = __in_ms.ms_prime_sealed;
	int _tmp_size = __in_ms.ms_size;
	size_t _len_prime_sealed = _tmp_size;
	unsigned char* _in_prime_sealed = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_prime_sealed, _len_prime_sealed);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_prime_sealed != NULL && _len_prime_sealed != 0) {
		if ( _len_prime_sealed % sizeof(*_tmp_prime_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_prime_sealed = (unsigned char*)malloc(_len_prime_sealed)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_prime_sealed, 0, _len_prime_sealed);
	}
	_in_retval = ecall_get_rand_prime_sealed(_tmp_size, _in_prime_sealed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_prime_sealed) {
		if (memcpy_verw_s(_tmp_prime_sealed, _len_prime_sealed, _in_prime_sealed, _len_prime_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_prime_sealed) free(_in_prime_sealed);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_sealed_data(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_sealed_data_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_sealed_data_t* ms = SGX_CAST(ms_ecall_get_sealed_data_t*, pms);
	ms_ecall_get_sealed_data_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_sealed_data_t), ms, sizeof(ms_ecall_get_sealed_data_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_old_prime_sealed = __in_ms.ms_old_prime_sealed;
	int _tmp_size = __in_ms.ms_size;
	size_t _len_old_prime_sealed = _tmp_size;
	unsigned char* _in_old_prime_sealed = NULL;
	unsigned char* _tmp_new_prime_sealed = __in_ms.ms_new_prime_sealed;
	size_t _len_new_prime_sealed = _tmp_size;
	unsigned char* _in_new_prime_sealed = NULL;
	int _in_retval;

	CHECK_UNIQUE_POINTER(_tmp_old_prime_sealed, _len_old_prime_sealed);
	CHECK_UNIQUE_POINTER(_tmp_new_prime_sealed, _len_new_prime_sealed);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_old_prime_sealed != NULL && _len_old_prime_sealed != 0) {
		if ( _len_old_prime_sealed % sizeof(*_tmp_old_prime_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_old_prime_sealed = (unsigned char*)malloc(_len_old_prime_sealed);
		if (_in_old_prime_sealed == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_old_prime_sealed, _len_old_prime_sealed, _tmp_old_prime_sealed, _len_old_prime_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_new_prime_sealed != NULL && _len_new_prime_sealed != 0) {
		if ( _len_new_prime_sealed % sizeof(*_tmp_new_prime_sealed) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_new_prime_sealed = (unsigned char*)malloc(_len_new_prime_sealed)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_new_prime_sealed, 0, _len_new_prime_sealed);
	}
	_in_retval = ecall_get_sealed_data(_tmp_size, _in_old_prime_sealed, _in_new_prime_sealed);
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}
	if (_in_new_prime_sealed) {
		if (memcpy_verw_s(_tmp_new_prime_sealed, _len_new_prime_sealed, _in_new_prime_sealed, _len_new_prime_sealed)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_old_prime_sealed) free(_in_old_prime_sealed);
	if (_in_new_prime_sealed) free(_in_new_prime_sealed);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_get_size(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_get_size_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_get_size_t* ms = SGX_CAST(ms_ecall_get_size_t*, pms);
	ms_ecall_get_size_t __in_ms;
	if (memcpy_s(&__in_ms, sizeof(ms_ecall_get_size_t), ms, sizeof(ms_ecall_get_size_t))) {
		return SGX_ERROR_UNEXPECTED;
	}
	sgx_status_t status = SGX_SUCCESS;
	int _in_retval;


	_in_retval = ecall_get_size();
	if (memcpy_verw_s(&ms->ms_retval, sizeof(ms->ms_retval), &_in_retval, sizeof(_in_retval))) {
		status = SGX_ERROR_UNEXPECTED;
		goto err;
	}

err:
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_ecall_get_rand_prime_sealed, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_sealed_data, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_get_size, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


