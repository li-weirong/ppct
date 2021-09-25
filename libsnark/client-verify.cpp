#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <fstream>
#include "common.hpp"
using namespace libsnark;
using namespace std;
int main () {
    protoboard<FieldT> pb = build_protoboard(NULL);	//构造面包板
    fstream f_vk("client_vk.raw", ios_base::in);	// 加载verification key
    r1cs_gg_ppzksnark_verification_key<libff::default_ec_pp> client_vk;
    f_vk >> client_vk;
    f_vk.close();
    cout << "client_vk.raw is loaded" << endl;
    fstream f_proof("bank_proof.raw", ios_base::in);	// 加载银行生成的证明
    r1cs_gg_ppzksnark_proof<libff::default_ec_pp> bank_proof;
    f_proof >> bank_proof;
    f_proof.close();
    cout << "bank_proof.raw is loaded" << endl;
    bool verified = r1cs_gg_ppzksnark_verifier_strong_IC<default_r1cs_gg_ppzksnark_pp>(
        client_vk, pb.primary_input(), bank_proof);	//进行验证
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Verification status: " << verified << endl;	//查看验证结果
    return 0;
}
