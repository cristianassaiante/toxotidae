#include "hooks.h"
#include "toxotidae.h"
#include "hooks_parser.h"
#include "logging.h"

#include <fstream>
#include <iostream>


namespace Hooks
{
#ifdef PARAMS
	std::map<std::pair<std::string, ADDRINT>, std::vector<param_t>> parameters;
#endif // PARAMS

	std::map<std::pair<std::string, ADDRINT>, UINT> sp_offsets;


	VOID HookCallback(CONTEXT *ctx, THREADID tid, ADDRINT addr, ADDRINT img_addr, ADDRINT rtn, ADDRINT esp, const char* api_name, const char* dll_name)
	{
		ADDRINT offset = addr - img_addr;

		ADDRINT sp_offset = (addr == rtn) ? 0 : sp_offsets[{api_name, offset}];
		ADDRINT retaddr = *(ADDRINT*)(esp + sp_offset);

		if (!Toxotidae::isInsMainExecutable(retaddr)) return;

		std::stringstream out_stream;

#ifdef PARAMS
		std::vector<param_t> params = parameters[{api_name, offset}];
#endif // PARAMS

		out_stream << "[" << tid << "]\t ";

		if (addr == rtn) {
			out_stream << "ENT";
		}
		else {
			out_stream << "TOX";
		}
		out_stream << " AT 0x" << std::hex << offset << " TO 0x" << retaddr << std::dec << "\t |" << api_name << " (" << dll_name << ")|\t ";

#ifdef PARAMS
		if (params.empty()) return;

		out_stream << "{ ";

		for (auto param : params) {

			LEVEL_BASE::REG reg = param.base;
			ADDRINT content = PIN_GetContextReg(ctx, reg);

			out_stream << param.state << ": ";
			if (param.is_mem) {
				out_stream << "0x" << std::hex << *(UINT*)(content + param.offset) << std::dec << ", ";
			}
			else {
				out_stream << "0x" << std::hex << content << std::dec << ", ";
			}
		}

		out_stream << " }";
#endif	// PARAMS

		LOG_AR("%s", out_stream.str().c_str());
	}
}