#include <fstream>
#include "seal/seal.h"
using namespace std;
using namespace seal;

int main()
{
    fstream parms_istream("encryption_parms.raw", ios_base::in | ios::binary);
    fstream data_istream("encrypted_data.raw", ios_base::in | ios::binary);
    fstream result_ostream("encrypted_result.raw", ios_base::out | ios::binary);
    EncryptionParameters parms;
    parms.load(parms_istream);
    cout << "EncryptionParameters loaded from encryption_parms.raw" << endl;
    SEALContext context(parms);
    Evaluator evaluator(context);
    Ciphertext x1, y1;
    x1.load(context, data_istream);
    y1.load(context, data_istream);
    cout << "encrypted data loaded from encrypted_data.raw" << endl;
    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);    
    Plaintext x2, y2;
    encoder.encode(2.3, scale, x2);
    encoder.encode(2.5, scale, y2);
    Ciphertext encrypted_x, encrypted_y, encrypted_result;
    evaluator.sub_plain(x1, x2, encrypted_x);
    evaluator.sub_plain(y1, y2, encrypted_y);
    evaluator.square_inplace(encrypted_x);
    evaluator.square_inplace(encrypted_y);
    evaluator.add(encrypted_x, encrypted_y, encrypted_result);
    evaluator.mod_switch_to_next_inplace(encrypted_result);
    encrypted_result.save(result_ostream);
    cout << "encrypted result saved to encrypted_result.raw" << endl;
    return 0;
}
