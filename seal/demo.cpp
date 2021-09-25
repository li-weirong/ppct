#include <fstream>
#include "seal/seal.h"
using namespace std;
using namespace seal;

void demoLevel()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);
auto context_data = context.key_context_data();
cout << context_data->chain_index() << endl;
cout << hex;
for (const auto &prime : context_data->parms().coeff_modulus())
{
    cout << prime.value() << " ";
}
cout << dec << endl;
context_data = context.first_context_data();
while (context_data)
{
    cout << context_data->chain_index() << endl;
    context_data = context_data->next_context_data();
}    
}

void demoGetCurLevel()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    auto secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);
    Plaintext x_plain;
    encoder.encode(1.1, scale, x_plain);
    Encryptor encryptor(context, public_key);
Ciphertext x, xsquare;
encryptor.encrypt(x_plain, x);
Evaluator evaluator(context);
evaluator.square(x, xsquare); // xsquare在level 2，scale为2^80
cout << context.get_context_data(xsquare.parms_id())->chain_index() << endl;
cout << xsquare.scale() << endl;
}

void demoRescale()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    auto secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);

    double scale = pow(2.0, 40);
    CKKSEncoder encoder(context);
    Plaintext x_plain;
    encoder.encode(1.1, scale, x_plain);
    Encryptor encryptor(context, public_key);
    Ciphertext x, xsquare, y;
    encryptor.encrypt(x_plain, x);
    encryptor.encrypt(x_plain, y);
    Evaluator evaluator(context);
    cout << "a" << endl;
    evaluator.square(x, xsquare); // xsquare在level 2，scale为2^80
    evaluator.relinearize_inplace(xsquare, relin_keys);
    evaluator.rescale_to_next_inplace(xsquare); // xsquare层变为level 1，且重新缩放到2^80/P2
    cout << "a" << endl;
    evaluator.rescale_to_next_inplace(y);
    cout << "b" << endl;
    evaluator.multiply_inplace(xsquare, y); // xsquare在level 1，scale为2^120/P2
    cout << "a" << endl;
    evaluator.relinearize_inplace(xsquare, relin_keys);
    evaluator.rescale_to_next_inplace(xsquare); // xsquare层变为level 0，且重新缩放到2^120/(P2*P1)
    cout << "a" << endl;
    evaluator.rescale_to_next_inplace(y);
    cout << "b" << endl;
    evaluator.add_inplace(xsquare, y);
}

void demoAddInSameScale()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    auto secret_key = keygen.secret_key();

    CKKSEncoder encoder(context);
    Plaintext x_plain, y_plain;
    Encryptor encryptor(context, public_key);
    Ciphertext x, y;
    Evaluator evaluator(context);
double scale1 = pow(2.0, 40), scale2 = pow(2.0, 80);;
encoder.encode(1.1, scale1, x_plain);
encoder.encode(1.1, scale2, y_plain);
encryptor.encrypt(x_plain, x);
encryptor.encrypt(y_plain, y);
evaluator.add_inplace(x, y);		// x和y的scale不同，此处会抛scale mismatch的错误

}

void demoModSwitch()
{
    EncryptionParameters parms(scheme_type::ckks);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {60, 40, 40, 60}));
    SEALContext context(parms);

    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    auto secret_key = keygen.secret_key();

    CKKSEncoder encoder(context);
    Plaintext x_plain;
    Encryptor encryptor(context, public_key);
    Ciphertext x, xsq;
    Evaluator evaluator(context);
//假设生成的模系数素数分别为P0, P1, P2, P3, 这里P3是特殊模素数，不参与重新缩放
double scale = pow(2.0, 40);
encoder.encode(1.1, scale, x_plain);
encryptor.encrypt(x_plain, x);
evaluator.square(x, xsq);					// xsq在level 2，scale为2^80
evaluator.rescale_to_next_inplace(xsq);		// xsq层变为level 1，且重新缩放到2^80/P2
parms_id_type last_parms_id = xsq.parms_id();
evaluator.mod_switch_to_inplace(x, last_parms_id);
cout << (xsq.scale() == x.scale()) << endl;
xsq.scale() = pow(2.0, 40);
evaluator.add_inplace(xsq, x);
}

int main()
{
    demoAddInSameScale();
    return 0;
}
