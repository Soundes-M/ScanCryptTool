#include "POMMES.hpp"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>


static std::ifstream open_case_study_file() {

    const std::string relative_input_path =
    #if defined(REFRESH_CASE_STUDY)
        "examples/locality_refresh/pommes_locality_refresh_d2.c.019t.ssa";
    #elif defined(ISW_AND_CASE_STUDY)
        "examples/isw_and/pommes_isw_and_d1.c.019t.ssa";
    #elif defined(PINI_MULT_CASE_STUDY)
        "examples/pini_mult/pommes_pini_mult_d1.c.019t.ssa";
    #elif defined(SUBBYTE_RP)
        "examples/rp_sbox_subbytes_func/pommes_subbytes_rp_func_d1.c.019t.ssa";
    #elif defined(MULTSHARE)
        "examples/rp_sbox_multshare/pommes_multshare_d1.c.019t.ssa";
    #elif defined(SQUARE_SHARE)
        "examples/rp_sbox_squareshare/pommes_square_share_d1.c.019t.ssa";
    #elif defined(SQUARE)
        "examples/rp_sbox_square/pommes_square_d1.c.019t.ssa";
    #elif defined(MULTTABLE)
        "examples/rp_sbox_multtable/pommes_multtable_d1.c.019t.ssa";
    #else
        "";
    #endif

    if(relative_input_path.empty()){
        throw std::runtime_error("no case study macro defined in inc/POMMES.hpp");
    }

    const std::vector<std::string> path_prefixes = {"./", "../", "../../"};
    for(const auto& prefix: path_prefixes){
        const std::filesystem::path candidate = std::filesystem::path(prefix) / relative_input_path;
        if(std::filesystem::exists(candidate)){
            std::ifstream infile(candidate);
            if(infile.is_open()){
                std::cout << "[+] using input file: " << candidate.string() << std::endl;
                return infile;
            }
        }
    }

    throw std::runtime_error("could not open file");
}

int main(){

    std::ifstream infile = open_case_study_file();


    function func;
    virtual_variables_vec virtual_variables;
    gimple_parser(func, virtual_variables, infile);


    //matrix contains at position zero first basic block ,position one second basic block etc. 
    //the first basic block starts with basic block number 2
    std::vector<std::vector<uint8_t>> adjacency_matrix(func.bb.size(), std::vector<uint8_t>(func.bb.size(), 0));
    std::map<uint32_t, uint32_t> node_to_bb_number;
    build_graph(func, adjacency_matrix, node_to_bb_number);


    std::vector<bool> visited(adjacency_matrix.at(0).size(),false);
    std::vector<std::vector<uint32_t>> dependency_adjacent_matrix(virtual_variables.size());

    //perform sensitivity tracking on static instructions
    std::cout << "[-] taint tracking of variables through the program...";
    static_taint_tracking(func, adjacency_matrix, virtual_variables);
    std::cout << "done!" << std::endl;

    std::cout << "[-] generating assembly code..." << std::endl;
    generate_TAC(func, virtual_variables, adjacency_matrix);

}