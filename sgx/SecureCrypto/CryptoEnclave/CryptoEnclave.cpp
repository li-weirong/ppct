#include "CryptoEnclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include <cstring>
#include <cstdlib>
#include <cstdio>

sgx_ecc_state_handle_t ctx;
sgx_ec256_private_t p_private;
sgx_ec256_public_t p_public;

//ECDSA的密钥对，用于密封后保存到磁盘
typedef struct tcrypto_sealed_data {
    sgx_ec256_private_t p_private;
    sgx_ec256_public_t p_public;
}crypto_sealed_data_t;

//初始化ECDSA上下文，如果参数不为null，则从磁盘加载密钥文件，否则生成一个新的密钥对
int crypto_init(const char* sealed_data_file_name) {
    sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
    crypto_sealed_data_t* unsealed_data = NULL;
    sgx_sealed_data_t* enc_data = NULL;
    size_t enc_data_size;
    uint32_t dec_size = 0;
    ret = sgx_ecc256_open_context(&ctx);
    if (ret != SGX_SUCCESS)
        goto error;
    if (sealed_data_file_name != NULL) {
        //OCALL:从磁盘加载密钥文件
        ret = crypto_read_data(sealed_data_file_name, 
            (unsigned char**)&enc_data, &enc_data_size);
        if (ret != SGX_SUCCESS)
            goto error;
        dec_size = sgx_get_encrypt_txt_len(enc_data);
        if (dec_size != 0) {
            unsealed_data = (crypto_sealed_data_t*)malloc(dec_size);
            sgx_sealed_data_t* tmp = (sgx_sealed_data_t*)malloc(enc_data_size);
            //将数据拷贝到可信Enclave内存
            memcpy(tmp, enc_data, enc_data_size);
            //解封密钥
            ret = sgx_unseal_data(tmp, NULL, NULL, (uint8_t*)unsealed_data, &dec_size);
            if (ret != SGX_SUCCESS)
                goto error;
            p_private = unsealed_data->p_private;
            p_public = unsealed_data->p_public;
        }
    }
    else
        //生成一个新的密钥对
        ret = sgx_ecc256_create_key_pair(&p_private, &p_public, ctx);

error:
    if (unsealed_data != NULL)
        free(unsealed_data);
    return ret;
}

//将密钥对密封保存到磁盘
int crypto_seal_keys(const char* sealed_data_file_name) {
    sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
    sgx_sealed_data_t* sealed_data = NULL;
    uint32_t sealed_size = 0;
    crypto_sealed_data_t data;
    data.p_private = p_private;
    data.p_public = p_public;
    size_t data_size = sizeof(data);
    sealed_size = sgx_calc_sealed_data_size(NULL, data_size);
    if (sealed_size != 0){
        sealed_data = (sgx_sealed_data_t*)malloc(sealed_size);
        sgx_attributes_t attribute_mask;
        attribute_mask.flags = SGX_FLAGS_INITTED | SGX_FLAGS_DEBUG;
        attribute_mask.xfrm = 0;
        ret = sgx_seal_data_ex(SGX_KEYPOLICY_MRSIGNER, attribute_mask, 0xF0000000, 
            NULL, NULL, data_size, (uint8_t*)&data, sealed_size, sealed_data);
        if (ret == SGX_SUCCESS)
            ret = crypto_write_data(sealed_data_file_name, (unsigned char*)sealed_data, sealed_size);
        else
            free(sealed_data);
    }
    return ret;
}

//对消息进行签名，签名文件保存到磁盘
int crypto_sign(const char* message, void* signature, size_t sig_len) {
    sgx_status_t ret = SGX_ERROR_INVALID_PARAMETER;
    const size_t MAX_MESSAGE_LENGTH = 255;
    char signature_file_name[MAX_MESSAGE_LENGTH];
    snprintf(signature_file_name, MAX_MESSAGE_LENGTH, "%s.sig", message);
    ret = sgx_ecdsa_sign((uint8_t*)message, strnlen(message, MAX_MESSAGE_LENGTH), &p_private, (sgx_ec256_signature_t*)signature, ctx);
    if (ret == SGX_SUCCESS)
        ret = crypto_write_data(signature_file_name, (unsigned char*)signature, sizeof(sgx_ec256_signature_t));
    return ret;
}

//验证消息签名，验证通过返回SGX_EC_VALID，验证失败返回SGX_EC_INVALID_SIGNATURE
int crypto_verify(const char* message, void* signature, size_t sig_len) {
    const size_t MAX_MESSAGE_LENGTH = 255;
    uint8_t res;
    sgx_ec256_signature_t* sig = (sgx_ec256_signature_t*)signature;
    sgx_ecdsa_verify((uint8_t*)message, strnlen(message, MAX_MESSAGE_LENGTH), &p_public, sig, &res, ctx);
    return res;
}

//关闭清理ECDSA上下文
int crypto_close() {
    sgx_status_t ret = sgx_ecc256_close_context(ctx);
    return ret;
}