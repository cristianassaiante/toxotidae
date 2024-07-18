#include "hooks_parser.h"
#include "logging.h"
#include "hooks.h"

#include <fstream>
#include <iostream>

namespace HooksParser
{
	std::map<std::string, LEVEL_BASE::REG> registers;

#ifdef PARAMS
	VOID init_registersmap() {
		registers["A"] = REG_GAX;
		registers["B"] = REG_GCX;
		registers["C"] = REG_GDX;
		registers["D"] = REG_GBX;
		registers["E"] = REG_STACK_PTR;
		registers["F"] = REG_GBP;
		registers["G"] = REG_GSI;
		registers["H"] = REG_GDI;
		registers["g"] = REG_INST_PTR;
	#ifdef __LP64__
		registers["I"] = REG_R8;
		registers["J"] = REG_R9;
		registers["K"] = REG_R10;
		registers["L"] = REG_R11;
		registers["M"] = REG_R12;
		registers["N"] = REG_R13;
		registers["O"] = REG_R14;
		registers["P"] = REG_R15;
		registers["Q"] = REG_XMM0;
		registers["R"] = REG_XMM1;
		registers["S"] = REG_XMM2;
		registers["T"] = REG_XMM3;
		registers["U"] = REG_XMM4;
		registers["V"] = REG_XMM5;
		registers["W"] = REG_XMM6;
		registers["X"] = REG_XMM7;
		registers["Y"] = REG_XMM8;
		registers["Z"] = REG_XMM9;
		registers["a"] = REG_XMM10;
		registers["b"] = REG_XMM11;
		registers["c"] = REG_XMM12;
		registers["d"] = REG_XMM13;
		registers["e"] = REG_XMM14;
		registers["f"] = REG_XMM15;
	#endif	// __LP64__
	}

	// From: https://github.com/hasherezade/pe_utils/blob/master/dll_load/main.cpp
	static size_t split_list(const std::string &sline, const char delimiter, std::vector<std::string> &args)
	{
		std::stringstream f(sline);
		std::string s;
		while (std::getline(f, s, delimiter)) {
			args.push_back(s);
		}
		return args.size();
	}

	static VOID init_param(param_t &param, std::string key, UINT state, BOOL is_mem) {

		std::vector<std::string> tmp;
		split_list(key, '|', tmp);

		std::string base;
		INT offset = NULL;
		if (is_mem) {
			base = tmp[0];

			std::stringstream ss(tmp[1]);
			ss >> offset;
		}
		else {
			base = key;
		}

		param.base = registers[base];
		param.state = state;
		param.is_mem = is_mem;
		param.offset = offset;
	}

#endif	// PARAMS

	VOID parse_parameters(const std::string &filename) {

		std::ifstream file(filename.c_str());

		if (file.is_open()) {
			std::string line;
			while (std::getline(file, line)) {
				std::stringstream lines(line);
				std::string function;
				UINT nodes;

				lines >> function >> nodes;
				for (UINT i = 0; i < nodes; i++) {
					getline(file, line);

					std::stringstream node(line);
					UINT address;
					UINT nparams;
					UINT sp;

					node >> address >> nparams >> sp;

					Hooks::sp_offsets[{function, address}] = sp;

	#ifdef PARAMS
					for (UINT j = 0; j < nparams; j++) {
						std::getline(file, line);

						std::stringstream param(line);
						std::string key;
						UINT state;

						param >> key >> state;

						param_t p;
						init_param(p, key, state, key.find("|") != std::string::npos);
						Hooks::parameters[{function, address}].push_back(p);
					}
	#endif	// PARAMS
				}
			}
			file.close();
		}
	}
}