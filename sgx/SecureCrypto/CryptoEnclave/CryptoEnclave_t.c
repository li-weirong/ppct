#include "CryptoEnclave_t.h"

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


typedef struct ms_crypto_init_t {
	int ms_retval;
	const char* ms_sealed_data_file;
	size_t ms_sealed_data_file_len;
} ms_crypto_init_t;

typedef struct ms_crypto_seal_keys_t {
	int ms_retval;
	const char* ms_sealed_data_file;
	size_t ms_sealed_data_file_len;
} ms_crypto_seal_keys_t;

typedef struct ms_crypto_sign_t {
	int ms_retval;
	const char* ms_message;
	size_t ms_message_len;
	void* ms_signature;
	size_t ms_sig_len;
} ms_crypto_sign_t;

typedef struct ms_crypto_verify_t {
	int ms_retval;
	const char* ms_message;
	size_t ms_message_len;
	void* ms_signature;
	size_t ms_sig_len;
} ms_crypto_verify_t;

typedef struct ms_crypto_close_t {
	int ms_retval;
} ms_crypto_close_t;

typedef struct ms_crypto_write_data_t {
	const char* ms_file_name;
	const unsigned char* ms_p_data;
	size_t ms_len;
} ms_crypto_write_data_t;

typedef struct ms_crypto_read_data_t {
	const char* ms_file_name;
	unsigned char** ms_pp_data;
	size_t* ms_len;
} ms_crypto_read_data_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 4127)
#pragma warning(disable: 4200)
#endif

static sgx_status_t SGX_CDECL sgx_crypto_init(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_crypto_init_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_crypto_init_t* ms = SGX_CAST(ms_crypto_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_sealed_data_file = ms->ms_sealed_data_file;
	size_t _len_sealed_data_file = ms->ms_sealed_data_file_len ;
	char* _in_sealed_data_file = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data_file, _len_sealed_data_file);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data_file != NULL && _len_sealed_data_file != 0) {
		_in_sealed_data_file = (char*)malloc(_len_sealed_data_file);
		if (_in_sealed_data_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data_file, _len_sealed_data_file, _tmp_sealed_data_file, _len_sealed_data_file)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sealed_data_file[_len_sealed_data_file - 1] = '\0';
		if (_len_sealed_data_file != strlen(_in_sealed_data_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = crypto_init((const char*)_in_sealed_data_file);

err:
	if (_in_sealed_data_file) free(_in_sealed_data_file);
	return status;
}

static sgx_status_t SGX_CDECL sgx_crypto_seal_keys(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_crypto_seal_keys_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_crypto_seal_keys_t* ms = SGX_CAST(ms_crypto_seal_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_sealed_data_file = ms->ms_sealed_data_file;
	size_t _len_sealed_data_file = ms->ms_sealed_data_file_len ;
	char* _in_sealed_data_file = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_data_file, _len_sealed_data_file);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_data_file != NULL && _len_sealed_data_file != 0) {
		_in_sealed_data_file = (char*)malloc(_len_sealed_data_file);
		if (_in_sealed_data_file == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_sealed_data_file, _len_sealed_data_file, _tmp_sealed_data_file, _len_sealed_data_file)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_sealed_data_file[_len_sealed_data_file - 1] = '\0';
		if (_len_sealed_data_file != strlen(_in_sealed_data_file) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = crypto_seal_keys((const char*)_in_sealed_data_file);

err:
	if (_in_sealed_data_file) free(_in_sealed_data_file);
	return status;
}

static sgx_status_t SGX_CDECL sgx_crypto_sign(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_crypto_sign_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_crypto_sign_t* ms = SGX_CAST(ms_crypto_sign_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_message = ms->ms_message;
	size_t _len_message = ms->ms_message_len ;
	char* _in_message = NULL;
	void* _tmp_signature = ms->ms_signature;
	size_t _tmp_sig_len = ms->ms_sig_len;
	size_t _len_signature = _tmp_sig_len;
	void* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_message[_len_message - 1] = '\0';
		if (_len_message != strlen(_in_message) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		if ((_in_signature = (void*)malloc(_len_signature)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_signature, 0, _len_signature);
	}

	ms->ms_retval = crypto_sign((const char*)_in_message, _in_signature, _tmp_sig_len);
	if (_in_signature) {
		if (memcpy_s(_tmp_signature, _len_signature, _in_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_message) free(_in_message);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_crypto_verify(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_crypto_verify_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_crypto_verify_t* ms = SGX_CAST(ms_crypto_verify_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_message = ms->ms_message;
	size_t _len_message = ms->ms_message_len ;
	char* _in_message = NULL;
	void* _tmp_signature = ms->ms_signature;
	size_t _tmp_sig_len = ms->ms_sig_len;
	size_t _len_signature = _tmp_sig_len;
	void* _in_signature = NULL;

	CHECK_UNIQUE_POINTER(_tmp_message, _len_message);
	CHECK_UNIQUE_POINTER(_tmp_signature, _len_signature);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_message != NULL && _len_message != 0) {
		_in_message = (char*)malloc(_len_message);
		if (_in_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_message, _len_message, _tmp_message, _len_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_message[_len_message - 1] = '\0';
		if (_len_message != strlen(_in_message) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_signature != NULL && _len_signature != 0) {
		_in_signature = (void*)malloc(_len_signature);
		if (_in_signature == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_signature, _len_signature, _tmp_signature, _len_signature)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = crypto_verify((const char*)_in_message, _in_signature, _tmp_sig_len);

err:
	if (_in_message) free(_in_message);
	if (_in_signature) free(_in_signature);
	return status;
}

static sgx_status_t SGX_CDECL sgx_crypto_close(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_crypto_close_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_crypto_close_t* ms = SGX_CAST(ms_crypto_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = crypto_close();


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* call_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_crypto_init, 0, 0},
		{(void*)(uintptr_t)sgx_crypto_seal_keys, 0, 0},
		{(void*)(uintptr_t)sgx_crypto_sign, 0, 0},
		{(void*)(uintptr_t)sgx_crypto_verify, 0, 0},
		{(void*)(uintptr_t)sgx_crypto_close, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[7][5];
} g_dyn_entry_table = {
	7,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL crypto_write_data(const char* file_name, const unsigned char* p_data, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_name = file_name ? strlen(file_name) + 1 : 0;
	size_t _len_p_data = len;

	ms_crypto_write_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_crypto_write_data_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(file_name, _len_file_name);
	CHECK_ENCLAVE_POINTER(p_data, _len_p_data);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_name != NULL) ? _len_file_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_data != NULL) ? _len_p_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_crypto_write_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_crypto_write_data_t));
	ocalloc_size -= sizeof(ms_crypto_write_data_t);

	if (file_name != NULL) {
		ms->ms_file_name = (const char*)__tmp;
		if (_len_file_name % sizeof(*file_name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, file_name, _len_file_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_name);
		ocalloc_size -= _len_file_name;
	} else {
		ms->ms_file_name = NULL;
	}
	
	if (p_data != NULL) {
		ms->ms_p_data = (const unsigned char*)__tmp;
		if (_len_p_data % sizeof(*p_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, p_data, _len_p_data)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_data);
		ocalloc_size -= _len_p_data;
	} else {
		ms->ms_p_data = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL crypto_read_data(const char* file_name, unsigned char** pp_data, size_t* len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_file_name = file_name ? strlen(file_name) + 1 : 0;
	size_t _len_pp_data = sizeof(unsigned char*);
	size_t _len_len = sizeof(size_t);

	ms_crypto_read_data_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_crypto_read_data_t);
	void *__tmp = NULL;

	void *__tmp_pp_data = NULL;
	void *__tmp_len = NULL;

	CHECK_ENCLAVE_POINTER(file_name, _len_file_name);
	CHECK_ENCLAVE_POINTER(pp_data, _len_pp_data);
	CHECK_ENCLAVE_POINTER(len, _len_len);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (file_name != NULL) ? _len_file_name : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pp_data != NULL) ? _len_pp_data : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (len != NULL) ? _len_len : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_crypto_read_data_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_crypto_read_data_t));
	ocalloc_size -= sizeof(ms_crypto_read_data_t);

	if (file_name != NULL) {
		ms->ms_file_name = (const char*)__tmp;
		if (_len_file_name % sizeof(*file_name) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, file_name, _len_file_name)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_file_name);
		ocalloc_size -= _len_file_name;
	} else {
		ms->ms_file_name = NULL;
	}
	
	if (pp_data != NULL) {
		ms->ms_pp_data = (unsigned char**)__tmp;
		__tmp_pp_data = __tmp;
		if (_len_pp_data % sizeof(*pp_data) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_pp_data, 0, _len_pp_data);
		__tmp = (void *)((size_t)__tmp + _len_pp_data);
		ocalloc_size -= _len_pp_data;
	} else {
		ms->ms_pp_data = NULL;
	}
	
	if (len != NULL) {
		ms->ms_len = (size_t*)__tmp;
		__tmp_len = __tmp;
		if (_len_len % sizeof(*len) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_len, 0, _len_len);
		__tmp = (void *)((size_t)__tmp + _len_len);
		ocalloc_size -= _len_len;
	} else {
		ms->ms_len = NULL;
	}
	
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (pp_data) {
			if (memcpy_s((void*)pp_data, _len_pp_data, __tmp_pp_data, _len_pp_data)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (len) {
			if (memcpy_s((void*)len, _len_len, __tmp_len, _len_len)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

#ifdef _MSC_VER
#pragma warning(pop)
#endif
