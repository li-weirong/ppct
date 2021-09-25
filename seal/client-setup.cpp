#include <fstream>
#include "seal/seal.h"
using namespace std;
using namespace seal;

int main()
{
    fstream parms_ostream("encryption_parms.raw", ios_base::out | ios::binary);
    fstream sk_ostream("client_sk.raw", ios_base::out | ios::binary);
    fstream data_ostream("encrypted_data.raw", ios_base::out | ios::binary);
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));
    SEALContext context(parms);
    parms.save(parms_ostream);
    cout << "EncryptionParameters saved to encryption_parms.raw"<< endl;
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    auto secret_key = keygen.secret_key();
    secret_key.save(sk_ostream);
    cout << "secret_key saved to client_sk.raw"<< endl;
    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);
    Plaintext x1, y1;
    encoder.encode(1.3, scale, x1);
    encoder.encode(1.5, scale, y1);
    Encryptor encryptor(context, public_key);
    encryptor.set_secret_key(secret_key);
    encryptor.encrypt_symmetric(x1).save(data_ostream);
    encryptor.encrypt_symmetric(y1).save(data_ostream);
    cout << "encrypted data saved to encrypted_data.raw"<< endl;
    return 0;
}
