#ifndef CRYPTOENCLAVE_U_H__
#define CRYPTOENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef CRYPTO_WRITE_DATA_DEFINED__
#define CRYPTO_WRITE_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, crypto_write_data, (const char* file_name, const unsigned char* p_data, size_t len));
#endif
#ifndef CRYPTO_READ_DATA_DEFINED__
#define CRYPTO_READ_DATA_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, crypto_read_data, (const char* file_name, unsigned char** pp_data, size_t* len));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t crypto_init(sgx_enclave_id_t eid, int* retval, const char* sealed_data_file);
sgx_status_t crypto_seal_keys(sgx_enclave_id_t eid, int* retval, const char* sealed_data_file);
sgx_status_t crypto_sign(sgx_enclave_id_t eid, int* retval, const char* message, void* signature, size_t sig_len);
sgx_status_t crypto_verify(sgx_enclave_id_t eid, int* retval, const char* message, void* signature, size_t sig_len);
sgx_status_t crypto_close(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
