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


typedef struct ms_ecall_generate_password_t {
	int ms_retval;
	char* ms_p_value;
	int ms_p_length;
} ms_ecall_generate_password_t;

typedef struct ms_ecall_create_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_create_wallet_t;

typedef struct ms_ecall_show_wallet_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
} ms_ecall_show_wallet_t;

typedef struct ms_ecall_change_master_password_t {
	int ms_retval;
	const char* ms_old_password;
	size_t ms_old_password_len;
	const char* ms_new_password;
	size_t ms_new_password_len;
} ms_ecall_change_master_password_t;

typedef struct ms_ecall_add_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	const uint8_t* ms_item;
	size_t ms_item_size;
} ms_ecall_add_item_t;

typedef struct ms_ecall_remove_item_t {
	int ms_retval;
	const char* ms_master_password;
	size_t ms_master_password_len;
	int ms_index;
} ms_ecall_remove_item_t;

typedef struct ms_ocall_save_wallet_t {
	int ms_retval;
	uint8_t* ms_wallet;
	size_t ms_wallet_size;
} ms_ocall_save_wallet_t;

typedef struct ms_ocall_load_wallet_t {
	int ms_retval;
	uint8_t* ms_wallet;
	size_t ms_wallet_size;
} ms_ocall_load_wallet_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_ecall_generate_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_generate_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_generate_password_t* ms = SGX_CAST(ms_ecall_generate_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_p_value = ms->ms_p_value;
	int _tmp_p_length = ms->ms_p_length;
	size_t _len_p_value = _tmp_p_length * sizeof(char);
	char* _in_p_value = NULL;

	if (sizeof(*_tmp_p_value) != 0 &&
		(size_t)_tmp_p_length > (SIZE_MAX / sizeof(*_tmp_p_value))) {
		return SGX_ERROR_INVALID_PARAMETER;
	}

	CHECK_UNIQUE_POINTER(_tmp_p_value, _len_p_value);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_p_value != NULL && _len_p_value != 0) {
		if ( _len_p_value % sizeof(*_tmp_p_value) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_p_value = (char*)malloc(_len_p_value)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_p_value, 0, _len_p_value);
	}

	ms->ms_retval = ecall_generate_password(_in_p_value, _tmp_p_length);
	if (_in_p_value) {
		if (memcpy_s(_tmp_p_value, _len_p_value, _in_p_value, _len_p_value)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_p_value) free(_in_p_value);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_create_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_create_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_create_wallet_t* ms = SGX_CAST(ms_ecall_create_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_create_wallet((const char*)_in_master_password);

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_show_wallet(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_show_wallet_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_show_wallet_t* ms = SGX_CAST(ms_ecall_show_wallet_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_show_wallet((const char*)_in_master_password);

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_change_master_password(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_change_master_password_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_change_master_password_t* ms = SGX_CAST(ms_ecall_change_master_password_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_old_password = ms->ms_old_password;
	size_t _len_old_password = ms->ms_old_password_len ;
	char* _in_old_password = NULL;
	const char* _tmp_new_password = ms->ms_new_password;
	size_t _len_new_password = ms->ms_new_password_len ;
	char* _in_new_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_old_password, _len_old_password);
	CHECK_UNIQUE_POINTER(_tmp_new_password, _len_new_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_old_password != NULL && _len_old_password != 0) {
		_in_old_password = (char*)malloc(_len_old_password);
		if (_in_old_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_old_password, _len_old_password, _tmp_old_password, _len_old_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_old_password[_len_old_password - 1] = '\0';
		if (_len_old_password != strlen(_in_old_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_new_password != NULL && _len_new_password != 0) {
		_in_new_password = (char*)malloc(_len_new_password);
		if (_in_new_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_new_password, _len_new_password, _tmp_new_password, _len_new_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_new_password[_len_new_password - 1] = '\0';
		if (_len_new_password != strlen(_in_new_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_change_master_password((const char*)_in_old_password, (const char*)_in_new_password);

err:
	if (_in_old_password) free(_in_old_password);
	if (_in_new_password) free(_in_new_password);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_add_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_add_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_add_item_t* ms = SGX_CAST(ms_ecall_add_item_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;
	const uint8_t* _tmp_item = ms->ms_item;
	size_t _tmp_item_size = ms->ms_item_size;
	size_t _len_item = _tmp_item_size;
	uint8_t* _in_item = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);
	CHECK_UNIQUE_POINTER(_tmp_item, _len_item);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_item != NULL && _len_item != 0) {
		if ( _len_item % sizeof(*_tmp_item) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_item = (uint8_t*)malloc(_len_item);
		if (_in_item == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_item, _len_item, _tmp_item, _len_item)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = ecall_add_item((const char*)_in_master_password, (const uint8_t*)_in_item, _tmp_item_size);

err:
	if (_in_master_password) free(_in_master_password);
	if (_in_item) free(_in_item);
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_remove_item(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_remove_item_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_remove_item_t* ms = SGX_CAST(ms_ecall_remove_item_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_master_password = ms->ms_master_password;
	size_t _len_master_password = ms->ms_master_password_len ;
	char* _in_master_password = NULL;

	CHECK_UNIQUE_POINTER(_tmp_master_password, _len_master_password);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_master_password != NULL && _len_master_password != 0) {
		_in_master_password = (char*)malloc(_len_master_password);
		if (_in_master_password == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_master_password, _len_master_password, _tmp_master_password, _len_master_password)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_master_password[_len_master_password - 1] = '\0';
		if (_len_master_password != strlen(_in_master_password) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = ecall_remove_item((const char*)_in_master_password, ms->ms_index);

err:
	if (_in_master_password) free(_in_master_password);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_ecall_generate_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_create_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_show_wallet, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_change_master_password, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_add_item, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_remove_item, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[3][6];
} g_dyn_entry_table = {
	3,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_save_wallet(int* retval, uint8_t* wallet, size_t wallet_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_wallet = wallet_size;

	ms_ocall_save_wallet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_save_wallet_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(wallet, _len_wallet);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (wallet != NULL) ? _len_wallet : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_save_wallet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_save_wallet_t));
	ocalloc_size -= sizeof(ms_ocall_save_wallet_t);

	if (wallet != NULL) {
		ms->ms_wallet = (uint8_t*)__tmp;
		if (_len_wallet % sizeof(*wallet) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, wallet, _len_wallet)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_wallet);
		ocalloc_size -= _len_wallet;
	} else {
		ms->ms_wallet = NULL;
	}
	
	ms->ms_wallet_size = wallet_size;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_load_wallet(int* retval, uint8_t* wallet, size_t wallet_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_wallet = wallet_size;

	ms_ocall_load_wallet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_load_wallet_t);
	void *__tmp = NULL;

	void *__tmp_wallet = NULL;

	CHECK_ENCLAVE_POINTER(wallet, _len_wallet);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (wallet != NULL) ? _len_wallet : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_load_wallet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_load_wallet_t));
	ocalloc_size -= sizeof(ms_ocall_load_wallet_t);

	if (wallet != NULL) {
		ms->ms_wallet = (uint8_t*)__tmp;
		__tmp_wallet = __tmp;
		if (_len_wallet % sizeof(*wallet) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_wallet, 0, _len_wallet);
		__tmp = (void *)((size_t)__tmp + _len_wallet);
		ocalloc_size -= _len_wallet;
	} else {
		ms->ms_wallet = NULL;
	}
	
	ms->ms_wallet_size = wallet_size;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (wallet) {
			if (memcpy_s((void*)wallet, _len_wallet, __tmp_wallet, _len_wallet)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

