#pragma once

#include "pin.H"

// undefine this to avoid logging parameters
#define PARAMS

#ifdef __LP64__
#define HOOKS_BASEPATH "C:\\hooks\\64bit\\"
#else
#define HOOKS_BASEPATH "C:\\hooks\\32bit\\"
#endif	// __LP64__

typedef struct {
	LEVEL_BASE::REG base;
	INT offset;
	UINT state;
	BOOL is_mem;
} param_t;

namespace Hooks
{
#ifdef PARAMS
	extern std::map<std::pair<std::string, ADDRINT>, std::vector<param_t>> parameters;
#endif // PARAMS

	extern std::map<std::pair<std::string, ADDRINT>, UINT> sp_offsets;

	VOID HookCallback(CONTEXT *ctx, THREADID tid, ADDRINT addr, ADDRINT img_addr, ADDRINT rtn, ADDRINT esp, const char* api_name, const char* dll_name);
}