#include "CryptoEnclave_u.h"
#include <errno.h>

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

static sgx_status_t SGX_CDECL CryptoEnclave_crypto_write_data(void* pms)
{
	ms_crypto_write_data_t* ms = SGX_CAST(ms_crypto_write_data_t*, pms);
	crypto_write_data(ms->ms_file_name, ms->ms_p_data, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_crypto_read_data(void* pms)
{
	ms_crypto_read_data_t* ms = SGX_CAST(ms_crypto_read_data_t*, pms);
	crypto_read_data(ms->ms_file_name, ms->ms_pp_data, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * func_addr[7];
} ocall_table_CryptoEnclave = {
	7,
	{
		(void*)(uintptr_t)CryptoEnclave_crypto_write_data,
		(void*)(uintptr_t)CryptoEnclave_crypto_read_data,
		(void*)(uintptr_t)CryptoEnclave_sgx_oc_cpuidex,
		(void*)(uintptr_t)CryptoEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)(uintptr_t)CryptoEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)(uintptr_t)CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)(uintptr_t)CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};

sgx_status_t crypto_init(sgx_enclave_id_t eid, int* retval, const char* sealed_data_file)
{
	sgx_status_t status;
	ms_crypto_init_t ms;
	ms.ms_sealed_data_file = sealed_data_file;
	ms.ms_sealed_data_file_len = sealed_data_file ? strlen(sealed_data_file) + 1 : 0;
	status = sgx_ecall(eid, 0, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t crypto_seal_keys(sgx_enclave_id_t eid, int* retval, const char* sealed_data_file)
{
	sgx_status_t status;
	ms_crypto_seal_keys_t ms;
	ms.ms_sealed_data_file = sealed_data_file;
	ms.ms_sealed_data_file_len = sealed_data_file ? strlen(sealed_data_file) + 1 : 0;
	status = sgx_ecall(eid, 1, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t crypto_sign(sgx_enclave_id_t eid, int* retval, const char* message, void* signature, size_t sig_len)
{
	sgx_status_t status;
	ms_crypto_sign_t ms;
	ms.ms_message = message;
	ms.ms_message_len = message ? strlen(message) + 1 : 0;
	ms.ms_signature = signature;
	ms.ms_sig_len = sig_len;
	status = sgx_ecall(eid, 2, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t crypto_verify(sgx_enclave_id_t eid, int* retval, const char* message, void* signature, size_t sig_len)
{
	sgx_status_t status;
	ms_crypto_verify_t ms;
	ms.ms_message = message;
	ms.ms_message_len = message ? strlen(message) + 1 : 0;
	ms.ms_signature = signature;
	ms.ms_sig_len = sig_len;
	status = sgx_ecall(eid, 3, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t crypto_close(sgx_enclave_id_t eid, int* retval)
{
	sgx_status_t status;
	ms_crypto_close_t ms;
	status = sgx_ecall(eid, 4, &ocall_table_CryptoEnclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

