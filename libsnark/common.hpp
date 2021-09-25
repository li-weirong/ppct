#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/gadgetlib1/pb_variable.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
using namespace libsnark;
using namespace std;
typedef libff::Fr<default_r1cs_gg_ppzksnark_pp> FieldT;
protoboard<FieldT> build_protoboard(int* secret)
{
    default_r1cs_gg_ppzksnark_pp::init_public_params();
    protoboard<FieldT> pb;
    pb_variable<FieldT> min;			// VIP需要达到的财富指标
    pb_variable<FieldT> x;			// 银行知道但不能对外公布的用户财富值
    pb_variable<FieldT> less, less_or_eq;	// comparison_gadget需要用到的变量
    min.allocate(pb, "min");
    x.allocate(pb, "x");
    less.allocate(pb, "less"); 
    less_or_eq.allocate(pb, "less_or_eq");
    pb.set_input_sizes(1);				// 指标为可公开的值
    pb.val(min)= 99;					// 设置具体指标值为99（万）
    const size_t n = 16;				// 参与比较的数的比特位数
    comparison_gadget<FieldT> cmp(pb, n, min, x, less, less_or_eq, "cmp");		//构造gadget
    cmp.generate_r1cs_constraints();
    pb.add_r1cs_constraint(r1cs_constraint<FieldT>(less, 1, FieldT::one()));
    if( secret != NULL ) {	//银行在prove阶段传入secret，其他阶段为NULL
      pb.val(x) = *secret;    
      cmp.generate_r1cs_witness();
    }
    return pb;
}
