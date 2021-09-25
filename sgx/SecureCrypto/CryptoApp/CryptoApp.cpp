#include <iostream>
#include <Windows.h>
#include "sgx_urts.h"
#include "sgx_tcrypto.h"
#include "sgx_uae_service.h"
#include "CryptoEnclave_u.h"
#include "OptHelper.h"

long readFromFile(const char* file_name, unsigned char** pp_data) {
    FILE* infile;
    errno_t err;
    long fsize = 0;
    err = fopen_s(&infile, file_name, "rb");
    if (err == 0) {
        fseek(infile, 0L, SEEK_END);
        fsize = ftell(infile);
        rewind(infile);
        *pp_data = (unsigned char*)calloc(fsize, sizeof(unsigned char));
        unsigned char* tmp = *pp_data;
        size_t len = fread(tmp, sizeof(unsigned char), fsize, infile);
        fclose(infile);
    } else {
        printf("Failed to open File %s", file_name);
    }
    return fsize;
}

void crypto_write_data(const char* file_name, const unsigned char* p_data, size_t len) {
    FILE* outfile;
    errno_t err;
    err = fopen_s(&outfile, file_name, "wb");
    if (err == 0) {
        for (size_t i = 0; i < len; i++) {
            fputc(p_data[i], outfile);
        }
        fclose(outfile);
    }
    else {
        printf("Failed to open File %s", file_name);
    }
}

void crypto_read_data(const char* file_name, unsigned char** pp_data, size_t* len) {
    *len = readFromFile(file_name, pp_data);
}

typedef enum tCRYPTO_MODE {
    START,
    VERIFY,
    SIGN,
}crypto_mode_t;

int main(int argc, char* argv[]) {
    sgx_enclave_id_t   eid;
    sgx_status_t       ret = SGX_SUCCESS;
    sgx_launch_token_t token = { 0 };
    const wchar_t* ENCLAVE_FILE_NAME = L"CryptoEnclave.signed.dll";
    int updated = 0;
    char* failedInMethod = (char*)"SampleMethod";
    int res = -1;
    crypto_mode_t mode = START;
    int command;
    char* sig_file_name = NULL;
    char* export_key_file_name = NULL;
    char* sealed_data_name = NULL;
    char* message = NULL;

    char usage[] = "usage: %s [-e file_name] [-i sealed_keyfile] [-s message_to_sign] [-v message_to_verify -S signature_file]\n";
    while ((command = getopt(argc, argv, "e:i:s:v:S:")) != -1)
        switch (command) {
        case 'e':
            export_key_file_name = optarg;
            break;
        case 's':
            message = optarg;
            mode = SIGN;
            break;
        case 'v':
            message = optarg;
            mode = VERIFY;
            break;
        case 'S':
            sig_file_name = optarg;

            break;
        case 'i':
            sealed_data_name = optarg;
            break;
        case '?':
            fprintf(stderr, usage, argv[0]);
            return 1;
        default:
            abort();
        }
    if (mode == START)
        fprintf(stderr, usage, argv[0]);

    sgx_device_status_t sgx_device_status;

    ret = sgx_enable_device(&sgx_device_status);

    if (ret != SGX_SUCCESS) {
        failedInMethod = (char*)"sgx_enable_device";
        goto error;
    }

    ret = sgx_create_enclave(ENCLAVE_FILE_NAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

    if (ret != SGX_SUCCESS) {
        failedInMethod = (char*)"sgx_create_enclave";
        goto error;
    }

    ret = crypto_init(eid, &res, sealed_data_name);
    if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
        failedInMethod = (char*)"crypto_init";
        goto error;
    }

    switch (mode) {
    case VERIFY:
        if (sig_file_name != NULL) {
            sgx_ec256_signature_t* sig;
            readFromFile(sig_file_name, (unsigned char**)&sig);

            ret = crypto_verify(eid, &res, message, (void*)sig, sizeof(sgx_ec256_signature_t));
            if (ret != SGX_SUCCESS || res != SGX_EC_VALID) {
                failedInMethod = (char*)"crypto_verify";
                goto error;
            }
            printf("\nSignature of message %s successfully verified!\n", message);
            break;
        } else {
            fprintf(stderr, "Signature file not specified");
            goto error;
        }

    case SIGN:
        sgx_ec256_signature_t sig;
        ret = crypto_sign(eid, &res, message, (void*)&sig, sizeof(sgx_ec256_signature_t));
        if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
            failedInMethod = (char*)"crypto_sign";
            goto error;
        }
        printf("\nSignature of message %s successfully signed!\n", message);
        break;
    default:
        fprintf(stderr, "no mode specified (-v or -s)");
        goto error;
    }
    if (export_key_file_name != NULL) {
        ret = crypto_seal_keys(eid, &res, export_key_file_name);
        if (ret != SGX_SUCCESS || res != SGX_SUCCESS) {
            failedInMethod = (char*)"crypto_seal_keys";
            goto error;
        }
    }

    ret = crypto_close(eid, &res);

    error:
    if (ret != SGX_SUCCESS || (res != SGX_SUCCESS && res != SGX_EC_VALID)) {
        printf("\nApp: error %#x, failed in method: %s.\nMethod response: %d", ret, failedInMethod, res);
    }
    if (SGX_SUCCESS != sgx_destroy_enclave(eid)) // 卸载enclave
        return -1;
    return 0;
}