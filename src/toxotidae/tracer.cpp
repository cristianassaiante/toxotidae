#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <algorithm>

#include "toxotidae.h"
#include "unaligned_jmp.h"
#include "hooks_parser.h"
#include "hooks.h"
#include "logging.h"

using std::cerr;
using std::endl;
using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

std::ostream* out = &cerr;
std::ostream* main_log = &cerr;

bool unjmp_enabled;
bool only_entry_enabled;

// knobs for toxotidae
KNOB <BOOL> KnobUnalignedJmp(KNOB_MODE_WRITEONCE, "pintool",
	"unjmp", "false", "enable unaligned jmp detection");

// knob for onlyentry hook
KNOB <BOOL> KnobOnlyEntry(KNOB_MODE_WRITEONCE, "pintool",
	"onlyentry", "false", "enable only on-entry hooks");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage() {
	cerr << "This tool will trace all the API called by the given program." << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;
	return -1;
}

VOID LoadImage(IMG img, VOID *arg)
{
	ADDRINT img_start = IMG_LowAddress(img);
	ADDRINT img_end = IMG_HighAddress(img);

	std::string img_name = IMG_Name(img);
	std::string dll_name(img_name.substr(img_name.rfind("\\") + 1));
	std::transform(dll_name.begin(), dll_name.end(), dll_name.begin(), std::tolower);

	const char* dll_name_c = dll_name.c_str();
	dll_name_c = strdup(dll_name_c);

	if (IMG_IsMainExecutable(img)) {
		Toxotidae::setMainExecutable(img_start, img_end);
		return;
	}

	if (!Toxotidae::is_supported(dll_name)) return;

	std::string hooks_filename = HOOKS_BASEPATH + dll_name + ".hooks";

	HooksParser::parse_parameters(hooks_filename);

	std::set<std::pair<std::string, ADDRINT>> instrumented;

	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		if (strcmp(SEC_Name(sec).c_str(), ".text")) continue;

		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {

			std::string rtn_name = RTN_Name(rtn);
			if (!strcmp(rtn_name.c_str(), ".text")) continue;

			const char* tmp = rtn_name.c_str();
			const char* dllName = strdup(tmp);
			ADDRINT address = RTN_Address(rtn);

			if (unjmp_enabled) {
				UnalignedJmp::addApi(dllName, address, IMG_LowAddress(img), dll_name_c);
			}

			RTN_Open(rtn);

			int i = 0;
			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {

				ADDRINT addr = INS_Address(ins) - img_start;
				const char* rtn_name_c = rtn_name.c_str();
				rtn_name_c = strdup(rtn_name_c);

				if (i == 0 && only_entry_enabled) {
					if (!Hooks::sp_offsets.count({ rtn_name, addr })) continue;

					if (instrumented.count({ rtn_name, addr })) continue;

					INS_InsertCall(ins, IPOINT_BEFORE,
						(AFUNPTR)Hooks::HookCallback,
						IARG_CONTEXT,
						IARG_THREAD_ID,
						IARG_INST_PTR,
						IARG_ADDRINT, IMG_StartAddress(img),
						IARG_ADDRINT, RTN_Address(rtn),
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_ADDRINT, rtn_name_c,
						IARG_ADDRINT, dll_name_c,
						IARG_END);

					instrumented.insert({ rtn_name, addr });
					i++;
					continue;
				}

				if (!only_entry_enabled) {
					if (!Hooks::sp_offsets.count({ rtn_name, addr })) continue;

					if (instrumented.count({ rtn_name, addr })) continue;

					INS_InsertCall(ins, IPOINT_BEFORE,
						(AFUNPTR)Hooks::HookCallback,
						IARG_CONTEXT,
						IARG_THREAD_ID,
						IARG_INST_PTR,
						IARG_ADDRINT, IMG_StartAddress(img),
						IARG_ADDRINT, RTN_Address(rtn),
						IARG_REG_VALUE, REG_STACK_PTR,
						IARG_ADDRINT, rtn_name_c,
						IARG_ADDRINT, dll_name_c,
						IARG_END);

					instrumented.insert({ rtn_name, addr });
				}
			}

			RTN_Close(rtn);
		}
	}

	return;
}

VOID Fini(INT32 code, VOID* v)
{
	cerr << "=====================================================" << endl;
	cerr << "toxotidae ended its execution. " << endl;
	cerr << "=====================================================" << endl;

	Logging::Shutdown();
}

int main(int argc, char* argv[]) {
	PIN_InitSymbols();

	if (PIN_Init(argc, argv)) {
		return Usage();
	}

	Toxotidae::init();
	Logging::Init();

	unjmp_enabled = KnobUnalignedJmp.Value();
	only_entry_enabled = KnobOnlyEntry.Value();

	if (unjmp_enabled) {
		INS_AddInstrumentFunction(UnalignedJmp::InstrumentIndirect, NULL);
	}

	IMG_AddInstrumentFunction(LoadImage, NULL);
	PIN_AddFiniFunction(Fini, 0);

	cerr << "===============================================" << endl;
	cerr << "This application is instrumented by toxotidae" << endl;
	cerr << "===============================================" << endl;

	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
