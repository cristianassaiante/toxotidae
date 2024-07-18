#pragma once

#include "pin.H"
#include <set>

namespace UnalignedJmp
{
	extern std::map<ADDRINT, std::pair<const char*, ADDRINT>> apis;
	extern std::set<ADDRINT> addresses;
	extern std::map<ADDRINT, const char*> images;

	VOID addApi(const char* name, ADDRINT addr, ADDRINT imgbase, const char* dll);

	BOOL isTargetValidAddress(ADDRINT addr);
	const char *getTargetAPI(ADDRINT addr, UINT *delta, ADDRINT *imgbase);

	VOID deleteApis();

	VOID validateTransfer(ADDRINT addr, THREADID tid, ADDRINT bt);

	VOID InstrumentIndirect(INS ins, VOID* p);
}