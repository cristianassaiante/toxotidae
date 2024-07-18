#pragma once

#include "pin.H"

namespace Toxotidae
{
	extern ADDRINT mainExecutableLow;
	extern ADDRINT mainExecutableHigh;

	extern std::vector<std::string> supported_dll;

	VOID setMainExecutable(ADDRINT low, ADDRINT high);
	BOOL isInsMainExecutable(ADDRINT addr);

	VOID init();
	BOOL is_supported(std::string &dllname);
}