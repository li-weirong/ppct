#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <fstream>
#include "common.hpp"
using namespace libsnark;
using namespace std;
int main (int argc, char* argv[]) {
    if(argc != 2) {		// 对输入进行合法性校验
        cout << "Please input the secret number." << endl;
        return -1;
    }
    int secret;
    try {
        secret = stoi(argv[1]);
    } catch (...) {
        cout << "Incorrect format. Please input an integer as a secret." << endl;
        return -1;
    }
    protoboard<FieldT> pb = build_protoboard(&secret);	//输入隐私数据构造面包板
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    if (!pb.is_satisfied()) {		//验证面包板合法性
        cout << "pb is not satisfied" << endl;
        return -1;
    }
    fstream f_pk("bank_pk.raw", ios_base::in);		//加载proving key
    r1cs_gg_ppzksnark_proving_key<libff::default_ec_pp> bank_pk;
    f_pk >> bank_pk;
    f_pk.close();
    cout << "bank_pk.raw is loaded" << endl;
    const r1cs_gg_ppzksnark_proof<default_r1cs_gg_ppzksnark_pp> proof = 
        r1cs_gg_ppzksnark_prover<default_r1cs_gg_ppzksnark_pp>(
            bank_pk, pb.primary_input(), pb.auxiliary_input());	//生成证明
    fstream pr("bank_proof.raw", ios_base::out);		// 将生成的证明保存到bank_proof.raw文件
    pr << proof;
    pr.close();
    cout << "bank_proof.raw is exported" << endl;
    return 0;
}
