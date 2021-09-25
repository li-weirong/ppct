#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <fstream>
#include "common.hpp"
using namespace libsnark;
using namespace std;
int main () {
    protoboard<FieldT> pb = build_protoboard(NULL);
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();
    cout << "Primary (public) input: " << pb.primary_input() << endl;
    cout << "Auxiliary (private) input: " << pb.auxiliary_input() << endl;
    const r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = 
        r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(constraint_system);
    fstream pk("bank_pk.raw", ios_base::out);	//保存proving key到文件bank_pk.raw
    pk << keypair.pk;
    pk.close();
    cout << "bank_pk.raw is exported" << endl;
    fstream vk("client_vk.raw", ios_base::out);	//保存verification key到文件client_vk.raw
    vk << keypair.vk;
    vk.close();
    cout << "client_vk.raw is exported" << endl;
    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;
    return 0;
}
