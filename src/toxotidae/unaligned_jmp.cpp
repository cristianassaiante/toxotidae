#include "unaligned_jmp.h"

#include "toxotidae.h"
#include "logging.h"

#include <iostream>

namespace UnalignedJmp
{
	std::map<ADDRINT, std::pair<const char*, ADDRINT>> apis;
	std::set<ADDRINT> addresses;
	std::map<ADDRINT, const char*> images;

	VOID addApi(const char* name, ADDRINT addr, ADDRINT imgbase, const char* dll)
	{
		if (apis.count(addr)) return;

		apis[addr] = { name, imgbase };
		addresses.insert(addr);
		images[imgbase] = dll;
	}

	BOOL isTargetValidAddress(ADDRINT addr)
	{
		return addresses.count(addr) != 0;
	}

	static ADDRINT findClosest(ADDRINT addr, ADDRINT *next)
	{
		auto it = addresses.lower_bound(addr);
		if (it == addresses.begin())
			return -1;
		else {
			*next = *it;
			return *(--it);
		}
	}

	static const char *getDllName(ADDRINT imgbase)
	{
		if (!images.count(imgbase)) return NULL;
		return images[imgbase];
	}

	const char *getTargetAPI(ADDRINT addr, UINT* delta, ADDRINT* imgbase)
	{
		ADDRINT next;
		ADDRINT closestAPI = findClosest(addr, &next);
		if (closestAPI == -1)
			return NULL;

		if ((next - addr) <= 4)
			return NULL;

		*delta = addr - closestAPI;
		*imgbase = apis[closestAPI].second;
		return apis[closestAPI].first;
	}

	VOID deleteApis()
	{
		for (auto api : apis) {
			free((void*)api.second.first);
		}
	}

	VOID validateTransfer(ADDRINT addr, THREADID tid, ADDRINT bt)
	{	
		if (Toxotidae::isInsMainExecutable(bt)) return;

		UINT delta;
		ADDRINT imgbase;

		if (isTargetValidAddress(bt)) {
			return;
		}

		const char *apiName = getTargetAPI(bt, &delta, &imgbase);
		const char *dll = getDllName(imgbase);
		if (apiName) {
			LOG_AR("[Toxotidae] jmp/call to %s from 0x%x (bt=0x%x, delta=0x%x, base=0x%x, dll=%s", apiName, addr, bt, delta, imgbase, dll);
			return;
		}
	}


	VOID InstrumentIndirect(INS ins, VOID* p)
	{
		ADDRINT addr = INS_Address(ins);

		if (!Toxotidae::isInsMainExecutable(addr)) return;

		if (INS_IsBranchOrCall(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR)UnalignedJmp::validateTransfer,
				IARG_INST_PTR,
				IARG_THREAD_ID,
				IARG_BRANCH_TARGET_ADDR,
				IARG_ADDRINT,
				IARG_END);
		}
	}
};
