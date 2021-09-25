#include <fstream>
#include <iomanip>
#include <math.h>
#include "seal/seal.h"
using namespace std;
using namespace seal;

int main()
{
    fstream parms_istream("encryption_parms.raw", ios_base::in | ios::binary);
    fstream sk_istream("client_sk.raw", ios_base::in | ios::binary);
    fstream result_istream("encrypted_result.raw", ios_base::in | ios::binary);
    EncryptionParameters parms;
    parms.load(parms_istream);
    cout << "EncryptionParameters loaded from encryption_parms.raw" << endl;
    SEALContext context(parms);
    SecretKey sk;
    sk.load(context, sk_istream);
    cout << "client_sk loaded from client_sk.raw" << endl;
    Decryptor decryptor(context, sk);
    CKKSEncoder encoder(context);
    Ciphertext encrypted_result;
    encrypted_result.load(context, result_istream);
    cout << "encrypted_result loaded from encrypted_result.raw" << endl;
    Plaintext plain_result;
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "Result: " << sqrt(result[0]) << endl;
    return 0;
}

